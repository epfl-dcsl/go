package gosec

import (
	"log"
	"reflect"
	"runtime"
	"unsafe"
)

// Slice of gosecure targets.
var gosecFunctions []interface{}

var secureMap map[string]func(size int32, argp *uint8)

// EcallServer keeps polling the Cooprt.Ecall queue for incoming gosecure calls.
// We cannot use reflect to get the value of the arguments. Instead, we need to
// create an equivalent type by going through unsafe.Pointer and type casting.
func EcallServer() {
	for {
		call := <-runtime.Cooprt.Ecall
		fn := reflect.ValueOf(gosecFunctions[call.Id])
		tpes := reflect.TypeOf(gosecFunctions[call.Id])
		var args []reflect.Value
		for i := range call.Args {
			ptr := call.Args[i]
			val := (reflect.NewAt(tpes.In(i), ptr)).Elem()
			args = append(args, val)
		}
		go fn.Call(args)
	}
}

func EcallServer2() {
	for {
		call := <-runtime.Cooprt.Ecall2
		//TODO here create the buffer of memory that will be used for the call.
		//We need to carefully copy the content and replace the function pointer.
		if fn := secureMap[call.Name]; fn != nil {
			log.Println("Making a call: ", call.Name, "argp is at", call.Argp)
			a := (*int)(unsafe.Pointer(call.Argp))
			log.Println("The value there ", *a)
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
	gosecFunctions = append(gosecFunctions, f)
}

// RegisterSecureFunction is called automatically at the begining of the enclave
// execution, and registers all the functions that are a target of the gosecure
// keyword.
func RegisterSecureFunction2(f interface{}) {
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
