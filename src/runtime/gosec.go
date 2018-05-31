package runtime

import (
	"unsafe"
)

type EcallAttr struct {
	Name string
	Siz  int32
	Argp *uint8 //TODO @aghosn not sure about this one.
	Buf  []uint8
}

type poolSudog struct {
	available int
	wg        *sudog
	isencl    bool
}

type CooperativeRuntime struct {
	Ecall chan EcallAttr
	argc  int32
	argv  **byte

	//TODO @aghosn need a lock here. Mutex should be enough
	// but might need to avoid futex call? Should only happen when last goroutine
	// goes to sleep, right?

	readyE waitq //Ready to be rescheduled
	readyO waitq

	pool [50]poolSudog //TODO @aghosn pool of sudog structs allocated in non-trusted.
}

// migrateCrossDomain takes ready routines from the cross domain queue and puts
// them in the global run queue.
// Scheduler must be locked, TODO @aghosn probably should try locking the Cooprt.
func migrateCrossDomain() {
	if Cooprt == nil {
		return
	}
	var queue *waitq = nil
	if isEnclave {
		queue = &(Cooprt.readyE)
	} else {
		queue = &(Cooprt.readyO)
	}

	for sg := queue.dequeue(); sg != nil; sg = queue.dequeue() {
		globrunqput(sg.g)
		sg.g = nil
		Cooprt.pool[sg.id].available = 1
	}
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
	Cooprt.Ecall, Cooprt.argc, Cooprt.argv = make(chan EcallAttr), -1, argv
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

func Newproc(ptr uintptr, argp *uint8, siz int32) {
	fn := &funcval{ptr}
	pc := getcallerpc()
	systemstack(func() {
		newproc1(fn, argp, siz, pc)
	})
}
