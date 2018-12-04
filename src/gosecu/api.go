package gosecu

import (
	"fmt"
	"reflect"
	"runtime"
)

// Slice of gosecure targets.
var (
	secureMap map[string]func(size int32, argp *uint8)
)

func privateServer(c chan runtime.EcallReq) {
	success := 0
	for {
		call := <-c
		if fn := secureMap[call.Name]; fn != nil {
			success++
			go fn(call.Siz, call.Argp)
		} else {
			panic("gosecu: illegal gosecure call.")
		}
	}
	fmt.Println("Closing the privateServer ", success)
	panic("Closing the shit")
}

// EcallServer keeps polling the Cooprt.Ecall queue for incoming private ecall
// server requests.
// We cannot use reflect to get the value of the arguments. Instead, we give
// a pointer to a buffer allocated inside the ecall attribute and use it to pass
// the arguments from the stack frame.
func EcallServer() {
	//Init the unprotected memory allocator
	for {
		req := <-runtime.Cooprt.EcallSrv
		if req.PrivChan == nil {
			continue
		}

		go privateServer(req.PrivChan)
	}
}

// RegisterSecureFunction is called automatically at the begining of the enclave
// execution, and registers all the functions that are a target of the gosecure
// keyword.
func RegisterSecureFunction(f interface{}) {
	if secureMap == nil {
		secureMap = make(map[string]func(size int32, argp *uint8))
		runtime.DebuggingShit()
	}

	ptr := reflect.ValueOf(f).Pointer()
	pc := runtime.FuncForPC(ptr)
	if pc == nil {
		//log.Fatalln("Unable to register secure function.")
		panic("Unable to register secure function.")
	}

	//TODO @aghosn that will not be enough probably. Should have a pointer instead?
	// or copy memory in a buffer inside the anonymous function?
	secureMap[pc.Name()] = func(size int32, argp *uint8) {
		runtime.Newproc(ptr, argp, size)
	}
}
