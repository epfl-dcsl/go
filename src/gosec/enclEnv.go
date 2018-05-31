package gosec

import (
	"log"
	"reflect"
	"runtime"
)

// Slice of gosecure targets.
var secureMap map[string]func(size int32, argp *uint8)

// EcallServer keeps polling the Cooprt.Ecall queue for incoming gosecure calls.
// We cannot use reflect to get the value of the arguments. Instead, we give
// a pointer to a buffer allocated inside the ecall attribute and use it to pass
// the arguments from the stack frame.
func EcallServer() {
	for {
		call := <-runtime.Cooprt.Ecall
		//TODO here create the buffer of memory that will be used for the call.
		//We need to carefully copy the content and replace the function pointer.
		if fn := secureMap[call.Name]; fn != nil {
			fn(call.Siz, call.Argp)
		} else {
			log.Fatalln("Unable to find secure func ", call.Name)
		}
	}
}

// RegisterSecureFunction is called automatically at the begining of the enclave
// execution, and registers all the functions that are a target of the gosecure
// keyword.
func RegisterSecureFunction(f interface{}) {
	if secureMap == nil {
		secureMap = make(map[string]func(size int32, argp *uint8))
	}

	ptr := reflect.ValueOf(f).Pointer()
	pc := runtime.FuncForPC(ptr)
	if pc == nil {
		log.Fatalln("Unable to register secure function.")
	}

	//TODO @aghosn that will not be enough probably. Should have a pointer instead?
	// or copy memory in a buffer inside the anonymous function?
	secureMap[pc.Name()] = func(size int32, argp *uint8) {
		runtime.Newproc(ptr, argp, size)
	}
}
