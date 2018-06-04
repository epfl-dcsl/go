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
	wg        *sudog
	isencl    bool
	available int
}

type CooperativeRuntime struct {
	Ecall chan EcallAttr
	argc  int32
	argv  **byte

	//TODO @aghosn need a lock here. Mutex should be enough
	// but might need to avoid futex call? Should only happen when last goroutine
	// goes to sleep, right?
	sl *secspinlock

	readyE waitq //Ready to be rescheduled
	readyO waitq

	//pool of sudog structs allocated in non-trusted.
	pool [50]*poolSudog
}

// checkinterdomain detects inter domain crossing and panics if foreign has
// higher protection than local. Returns true if local and foreign belong to
// different domains.
// This function is called when writting to a channel for example.
func checkinterdomain(rlocal, rforeign bool) bool {
	if !rlocal && rforeign {
		panic("An untrusted routine is trying to access a trusted channel")
	}
	return rlocal != rforeign
}

// migrateCrossDomain takes ready routines from the cross domain queue and puts
// them in the global run queue.
// Scheduler must be locked, as well as the Cooprt.
func migrateCrossDomain() {
	if Cooprt == nil {
		return
	}
	Cooprt.sl.Lock()
	var queue *waitq = nil
	if isEnclave {
		queue = &(Cooprt.readyE)
	} else {
		queue = &(Cooprt.readyO)
	}

	// Do not release the sudog yet. This is done when the routine is rescheduled.
	for sg := queue.dequeue(); sg != nil; sg = queue.dequeue() {
		if isEnclave != sg.g.isencl {
			panic("We do not access the correct queue -> SGX memory error.")
		}
		gp := sg.g
		gp.param = unsafe.Pointer(sg)
		goready(gp, 3+1)
		//globrunqput(sg.g)
	}
	Cooprt.sl.Unlock()
}

func acquireSudogFromPool() *sudog {
	if !isEnclave {
		panic("Acquiring fake sudog from non-trusted domain.")
	}
	Cooprt.sl.Lock()
	for i, x := range Cooprt.pool {
		if x.available != 0 {
			x.available = 0
			x.wg.id = int32(i)
			x.isencl = isEnclave
			Cooprt.sl.Unlock()
			return x.wg
		}
	}
	//TODO @aghosn should come up with something here.
	Cooprt.sl.Unlock()
	panic("Ran out of sudog in the pool.")
	return nil
}

// crossReleaseSudog calls the appropriate releaseSudog version depending on whether
// the sudog is a crossdomain one or not.
func crossReleaseSudog(sg *sudog) {
	// Check if this is not from the pool and is same domain (regular path)
	if isReschedulable(sg) {
		releaseSudog(sg)
		return
	}

	// This is called from someone who just woke up.
	// We are executing and are in the correct domain.
	// Hence this is our first check: id != -1 implies we are in the enclave
	if sg.id != -1 && !isEnclave {
		panic("We have a pool sudog containing a non enclave element.")
	}

	// Second step is if we are from the pool (and we are inside the enclave),
	// We are runnable again. We just release the sudog from the pool.
	Cooprt.sl.Lock()
	Cooprt.pool[sg.id].isencl = false
	Cooprt.pool[sg.id].available = 1
	Cooprt.sl.Unlock()
}

// isReschedulable checks if a sudog can be directly rescheduled.
// For that, we require the sudog to not belong to the pool and for the unblocking
// routine to belong to the same domain as this sudog.
func isReschedulable(sg *sudog) bool {
	if sg == nil {
		panic("Calling isReschedulable with nil sudog.")
	}
	return (sg.id == -1 && !checkinterdomain(isEnclave, sg.g.isencl))
}

// crossGoready takes a sudog and makes it ready to be rescheduled.
// It picks the proper ready queue for the sudog in the cooperative runtime.
// This method should be called only once the isReschedulable returned false.
func (c *CooperativeRuntime) crossGoready(sg *sudog) {
	c.sl.Lock()
	// We are about to make ready a sudog that is not from the pool.
	// This can happen only when non-trusted has blocked on a channel.
	if sg.id == -1 {
		if sg.g.isencl || sg.g.isencl == isEnclave {
			panic("Misspredicted the crossdomain scenario.")
		}
		c.readyO.enqueue(sg)
		c.sl.Unlock()
		return
	}

	// TODO remove this check once we run in SGX
	if c.pool[sg.id].isencl != sg.g.isencl {
		panic("The fake sudog does not reflect the domain of its g.")
	}
	// We have a sudog from the pool.
	if c.pool[sg.id].isencl {
		c.readyE.enqueue(sg)
	} else {
		c.readyO.enqueue(sg)
	}
	c.sl.Unlock()
}

func AllocateOSThreadEncl(stack uintptr, fn unsafe.Pointer) {
	if isEnclave {
		panic("Should not allocate enclave from the enclave.")
	}
	addrArgc := stack - unsafe.Sizeof(argc)
	addrArgv := addrArgc - unsafe.Sizeof(argv)

	ptrArgc := (*int32)(unsafe.Pointer(addrArgc))
	*ptrArgc = argc

	// Initialize the Cooprt
	Cooprt = &CooperativeRuntime{}
	Cooprt.Ecall, Cooprt.argc, Cooprt.argv = make(chan EcallAttr), -1, argv
	Cooprt.sl = &secspinlock{0}
	for i := range Cooprt.pool {
		Cooprt.pool[i] = &poolSudog{&sudog{}, false, 1}
		Cooprt.pool[i].wg.id = int32(i)
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

// To remove
func GetIsEnclave() bool {
	return isEnclave
}
