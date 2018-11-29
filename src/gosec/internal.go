package gosec

import (
	"bytes"
	"debug/elf"
	"log"
	"os"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

func check(e error) {
	if e != nil {
		panic(e.Error())
	}
}

type funcval struct {
	fn uintptr
	// variable-size, fn-specific data here
}

var initOnce sync.Once

func LoadEnclave() {
	p, err := elf.Open(os.Args[0])
	check(err)

	enclave := p.Section(".encl")
	defer func() { check(p.Close()) }()
	if enclave == nil {
		log.Fatalf("Binary %v does not contain an enclave section.", os.Args[0])
	}

	bts, err := enclave.Data()
	check(err)

	// Remove the header by seeking the magic bytes.
	magic := []byte{0x7F, 0x45, 0x4C, 0x46}
	var i = 0
	for i = 0; i < len(bts)-len(magic); i++ {
		if bytes.Compare(bts[i:i+len(magic)], magic) == 0 {
			break
		}
	}
	if i >= len(bts)-len(magic) {
		log.Fatalf("Unable to find the start of the executable in the encl section.")
	}
	bts = bts[i:]
	name := "enclavebin"
	encl, err := os.Create(name)
	check(err)
	defer func() { check(encl.Close()) }()

	check(os.Chmod(name, 0755))

	_, err = encl.Write(bts)
	check(err)

	//Start loading the program within the correct address space.
	simLoadProgram(name)
	//sgxLoadProgram(name)
}

func oCallServer() {
	runtime.MarkNoFutex()
	for {
		sys := <-runtime.Cooprt.Ocall
		var r1 uintptr
		var r2 uintptr
		var err syscall.Errno
		//TODO @aghosn maybe do that inside a goroutine.
		if sys.Big {
			r1, r2, err = syscall.Syscall6(sys.Trap, sys.A1, sys.A2, sys.A3, sys.A4, sys.A5, sys.A6)
		} else {
			r1, r2, err = syscall.Syscall(sys.Trap, sys.A1, sys.A2, sys.A3)
		}
		res := runtime.OcallRes{r1, r2, uintptr(err)}
		go runtime.Cooprt.SysSend(sys.Id, res)
	}
}

func bufcopy(dest []uint8, src *uint8, size int32) {
	ptr := uintptr(unsafe.Pointer(src))
	for i := uintptr(0); i < uintptr(size); i += unsafe.Sizeof(uint8(0)) {
		lptr := (*uint8)(unsafe.Pointer(ptr + i))
		dest[i] = *lptr
	}
}

// Gosecload has the same signature as newproc().
// It creates the enclave if it does not exist yet, and write to the cooperative channel.
//go:nosplit
func Gosecload(size int32, fn *funcval, b uint8) {
	pc := runtime.FuncForPC(fn.fn)
	if pc == nil {
		log.Fatalln("Unable to find the name for the func at address ", fn.fn)
	}

	initOnce.Do(func() {
		runtime.InitCooperativeRuntime()
		LoadEnclave()
		// Server to allocate requests & service system calls for the enclave.
		go oCallServer()
		//go allocServer()
		//go runtime.AvoidDeadlock()
	})

	//Copy the stack frame inside a buffer.
	attrib := runtime.EcallReq{Name: pc.Name(), Siz: size, Buf: nil, Argp: nil}
	if size > 0 {
		attrib.Buf = make([]uint8, size, size)
		bufcopy(attrib.Buf, &b, size)
		attrib.Argp = (*uint8)(unsafe.Pointer(&(attrib.Buf[0])))
	}
	runtime.GosecureSend(attrib)
}

func ThreadServer() {
	prot := int(_PROT_READ | _PROT_WRITE)
	manon := _MAP_ANON | _MAP_FIXED | _MAP_PRIVATE
	for i := 1; i < NBTCS; i++ {
		addresses := <-runtime.Cooprt.ThreadChan
		//[X]create the stack.
		//[X]put arguments on it.
		//[]call start
		if srcWrap == nil || enclWrap == nil || enclWrap.tcss[i].used {
			panic("Trying to spawn a thread without metadata.")
		}
		src := &srcWrap.tcss[i]
		dest := &srcWrap.tcss[i]

		//Mark them as used
		src.used = true
		dest.used = true

		//Mmap the source switch stack, i.e., non protected memory.
		_, ret := syscall.RMmap(src.stack, int(src.ssiz), prot, manon, -1, 0)
		check(ret)
		swsptr := src.stack + src.ssiz

		// Address for g - 56 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs := (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(addresses.Gp)

		// Address for m - 48 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(addresses.Mp)

		//Setup the argument on the stack for early setup.
		// protected stack address - 40 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(dest.stack + dest.ssiz - unsafe.Sizeof(dest.stack))

		// msgx address - 32 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(dest.msgx - TLS_MSGX_OFF)

		//Put the arguments for the sgxEEnter
		rdi, rsi := uint64(0), uint64(0)

		// RSI - 24 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(uintptr(unsafe.Pointer(&rsi)))

		// RDI - 16 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(uintptr(unsafe.Pointer(&rdi)))

		// Xception - 8 RSP
		xcpt := uint64(reflect.ValueOf(asm_exception).Pointer())
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = xcpt

		// tcs - 0 RSP
		swsptr -= unsafe.Sizeof(uint64(0))
		ptrs = (*uint64)(unsafe.Pointer(swsptr))
		*ptrs = uint64(dest.tcs)

		fn := unsafe.Pointer(reflect.ValueOf(asm_eenter).Pointer())
		runtime.StartEnclaveOSThread(swsptr, fn)
	}
}
