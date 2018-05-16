package runtime

import (
	"unsafe"
)

func AllocateOSThreadEncl(stack uintptr, fn unsafe.Pointer) {
	//if secp != nil {
	//	throw("secp is already allocated.\n")
	//}
	//throw("Okay we are here.")
	addrArgc := stack - unsafe.Sizeof(argc)
	addrArgv := addrArgc - unsafe.Sizeof(argv)

	ptrArgc := (*int32)(unsafe.Pointer(addrArgc))
	*ptrArgc = argc

	ptrArgv := (***byte)(unsafe.Pointer(addrArgv))
	*ptrArgv = argv

	ret := clone(cloneFlags, unsafe.Pointer(addrArgv), nil, nil, fn)
	if ret < 0 {
		write(2, unsafe.Pointer(&failthreadcreate[0]), int32(len(failthreadcreate)))
		exit(1)
	}

}

func Newproc(siz int32, ptr uintptr) {
	fn := &funcval{ptr}
	newproc(siz, fn)
}
