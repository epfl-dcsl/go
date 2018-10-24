package gosec

import (
	"bytes"
	"debug/elf"
	"log"
	"os"
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

// Spins on the scheduler. Avoids triggering the deadlock detector when routines
// are blocked on cross domain channels.
//TODO @aghosn try not to use this anymore, instead have it in syscall server.
//func avoidDeadlock() {
//	runtime.AvoidDeadlock()
//}

func oCallServer() {
	for {
		sys := <-runtime.Cooprt.Ocall
		var r1 uintptr
		var r2 uintptr
		var err syscall.Errno
		if sys.Big {
			r1, r2, err = syscall.Syscall6(sys.Trap, sys.A1, sys.A2, sys.A3, sys.A4, sys.A5, sys.A6)
		} else {
			r1, r2, err = syscall.Syscall(sys.Trap, sys.A1, sys.A2, sys.A3)
		}
		res := runtime.OcallRes{r1, r2, uintptr(err)}
		go runtime.Cooprt.SysSend(sys.Id, res)
	}
}

func allocServer() {
	for {
		allocBytes := <-runtime.Cooprt.OAllocReq
		if allocBytes.Siz > 0 {
			//TODO @aghosn check if this correct (garbage collected?)
			copy := &runtime.AllocAttr{allocBytes.Siz, make([]byte, allocBytes.Siz), allocBytes.Id}
			go runtime.Cooprt.AllocSend(allocBytes.Id, copy)
		} else {
			panic("Request for a non positive size allocation.")
		}
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
		go allocServer()
		go runtime.AvoidDeadlock()
	})

	//Copy the stack frame inside a buffer.
	attrib := runtime.EcallAttr{Name: pc.Name(), Siz: size, Buf: nil, Argp: nil}
	if size > 0 {
		attrib.Buf = make([]uint8, size, size)
		bufcopy(attrib.Buf, &b, size)
		attrib.Argp = (*uint8)(unsafe.Pointer(&(attrib.Buf[0])))
	}
	runtime.Cooprt.Ecall <- attrib
}
