package runtime

import (
	"unsafe"
)

type ECallAttr struct {
	Id   int32
	Args []unsafe.Pointer
}

type poolSudog struct {
	available int
	wg        *sudog
	isencl    bool
}

type CooperativeRuntime struct {
	Ecall chan ECallAttr
	argc  int32
	argv  **byte

	//TODO @aghosn need a lock here. Mutex should be enough
	// but might need to avoid futex call? Should only happen when last goroutine
	// goes to sleep, right?
	etoo *sudog //Blocked TODO @aghosn might need pointer to chan?
	otoe *sudog

	readyE waitq //Ready to be rescheduled
	readyO waitq

	pool [50]poolSudog //TODO @aghosn pool of sudog structs allocated in non-trusted.
}

func (c *CooperativeRuntime) tryGoReady(sg *sudog) bool {
	// Can we treat it as same domain. If so, use the go channel regular code.
	// TODO @aghosn do not forget to modify  goready
	if c.pool[sg.id].isencl == isEnclave {
		return true
	}
	// Do not release the sudog yet. This will be done when we reschedule g.
	if c.pool[sg.id].isencl {
		c.readyE.enqueue(sg)
	} else {
		c.readyO.enqueue(sg)
	}
	return false
}

func AllocateOSThreadEncl(stack uintptr, fn unsafe.Pointer) {
	//if secp != nil {
	//	throw("secp is already allocated.\n")
	//}
	//throw("Okay we are here.")
	addrArgc := stack - unsafe.Sizeof(argc)
	addrArgv := addrArgc - unsafe.Sizeof(argv)

	ptrArgc := (*int32)(unsafe.Pointer(addrArgc))
	*ptrArgc = argc

	// Initialize the Cooprt
	Cooprt = &CooperativeRuntime{}
	Cooprt.Ecall, Cooprt.argc, Cooprt.argv = make(chan ECallAttr), -1, argv
	Cooprt.etoo, Cooprt.otoe = nil, nil
	//Cooprt.readyE, Cooprt.readyO = nil, nil
	for i := range Cooprt.pool {
		Cooprt.pool[i].wg = &sudog{}
		Cooprt.pool[i].wg.id = int32(i)
		Cooprt.pool[i].available = 1
		Cooprt.pool[i].isencl = false
	}

	ptrArgv := (***byte)(unsafe.Pointer(addrArgv))
	*ptrArgv = (**byte)(unsafe.Pointer(Cooprt))

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
