package gosec

import (
	"fmt"
	"reflect"
	"runtime"
)

// Slice of gosecure targets.
var gosecFunctions []interface{}

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
			fmt.Printf("The shit shit %v\n", val)
			args = append(args, val)
		}
		go fn.Call(args)
	}
}

// RegisterSecureFunction is called automatically at the begining of the enclave
// execution, and registers all the functions that are a target of the gosecure
// keyword.
func RegisterSecureFunction(f interface{}) {
	gosecFunctions = append(gosecFunctions, f)
}
