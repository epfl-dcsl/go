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

func asm_oentry(req *runtime.SpawnRequest)

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

	//Setup the OEntry in Cooprt for extra threads
	runtime.Cooprt.OEntry = reflect.ValueOf(asm_oentry).Pointer()
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

// executes without g, m, or p, so might need to do better.
func spawnEnclaveThread(req *runtime.SpawnRequest) {
	// TODO @aghosn will need a lock here.
	for i := range enclWrap.tcss {
		if enclWrap.tcss[i].Used {
			continue
		}
		src := &srcWrap.tcss[i]
		dest := &enclWrap.tcss[i]
		src.Used, dest.Used = true, true
		//TODO unlock now.

		sgxEEnter(uint64(i), dest, src, req)
		// In the simulation we just return.
		if enclWrap.isSim {
			//TODO this is buggy right now.
			//just loop forever to debugg the other issue and come back to that.
			for {
			}
			return
		}
		// For sgx, we call eresume
		sgxEResume(req.Sid)
	}
	panic("gosec: unable to find an available tcs")
}

//TODO place holder for the moment
func sgxEResume(id uint64) {
	for {
	}
}
