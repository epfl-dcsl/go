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

//TODO @aghosn Debugging right now, remove after
const DEBUGMASK = 0x060000000000

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

func asm_oentry(req *runtime.OExitRequest)

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

	//Mmap debugging region
	prot := _PROT_READ | _PROT_WRITE
	manon := _MAP_PRIVATE | _MAP_ANON | _MAP_FIXED
	_, err = syscall.RMmap(DEBUGMASK, 0x1000, prot, manon, -1, 0)
	check(err)
	defer func() { check(encl.Close()) }()

	check(os.Chmod(name, 0755))

	_, err = encl.Write(bts)
	check(err)

	//Setup the OEntry in Cooprt for extra threads
	runtime.Cooprt.OEntry = reflect.ValueOf(asm_oentry).Pointer()
	//Start loading the program within the correct address space.
	if s := os.Getenv("SIM"); s != "" {
		simLoadProgram(name)
	} else {
		sgxLoadProgram(name)
	}
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

// executes without g, m, or p, so might need to do better.
//go:nosplit
func spawnEnclaveThread(req *runtime.OExitRequest) {
	if !enclWrap.tcss[req.Did].Used {
		panic("Error, tcs is not reserved.")
	}
	src := &srcWrap.tcss[req.Did]
	dest := &enclWrap.tcss[req.Did]
	src.Used, dest.Used = true, true

	sgxEEnter(uint64(req.Did), dest, src, req)
	// In the simulation we just return.
	if enclWrap.isSim {
		return
	}
	// For sgx, we call eresume
	sgxEResume(req.Sid)
	panic("gosec: unable to find an available tcs")
}

//go:nosplit
func FutexSleep(req *runtime.OExitRequest) {
	runtime.FutexsleepE(unsafe.Pointer(req.Addr), req.Val)
	if enclWrap.isSim {
		return
	}
	sgxEResume(req.Sid)
}

//go:nosplit
func FutexWakeup(req *runtime.OExitRequest) {
	runtime.FutexwakeupE(unsafe.Pointer(req.Addr), req.Val)
	if enclWrap.isSim {
		return
	}
	sgxEResume(req.Sid)
}

//go:nosplit
func sgxEResume(id uint64) {
	tcs := runtime.Cooprt.Tcss[id]
	xcpt := runtime.Cooprt.ExceptionHandler
	asm_eresume(uint64(tcs.Tcs), xcpt)
}
