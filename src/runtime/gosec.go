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

type OcallReq struct {
	Big  bool
	Trap uintptr
	A1   uintptr
	A2   uintptr
	A3   uintptr
	A4   uintptr
	A5   uintptr
	A6   uintptr
	Id   int
}

type OcallRes struct {
	R1  uintptr
	R2  uintptr
	Err uintptr
}

type AllocAttr struct {
	Siz int
	Buf []byte
	Id  int
}

type poolSysChan struct {
	id        int
	available int
	c         chan OcallRes
}

type poolAllocChan struct {
	id        int
	available int
	c         chan *AllocAttr
}

type poolSudog struct {
	wg        *sudog
	isencl    bool
	available int
}

type CooperativeRuntime struct {
	Ecall     chan EcallAttr
	Ocall     chan OcallReq
	OAllocReq chan AllocAttr

	argc int32
	argv **byte

	//TODO @aghosn need a lock here. Mutex should be enough
	// but might need to avoid futex call? Should only happen when last goroutine
	// goes to sleep, right?
	sl *secspinlock

	readyE waitq //Ready to be rescheduled
	readyO waitq

	//pool of sudog structs allocated in non-trusted.
	pool [50]*poolSudog

	//pool of answer channels.
	sysPool   [10]*poolSysChan
	allocPool [10]*poolAllocChan

	//Memory pool to satisfy the nil mmap calls.
	mmStart  uintptr
	currHead uintptr
}

const (
	IsSim = true
	//TODO @aghosn this must be exactly the same as in amd64/obj.go
	ENCLMASK = 0x040000000000
	POOLMEM  = uintptr(0x1000 * 300)
)

func IsEnclave() bool {
	return isEnclave
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

func (c *CooperativeRuntime) AcquireSysPool() (int, chan OcallRes) {
	c.sl.Lock()
	for i, s := range c.sysPool {
		if s.available == 1 {
			c.sysPool[i].available = 0
			c.sysPool[i].id = i
			c.sl.Unlock()
			return i, c.sysPool[i].c
		}
	}
	c.sl.Unlock()
	panic("Ran out of syspool channels.")
	return -1, nil
}

func (c *CooperativeRuntime) ReleaseSysPool(id int) {
	if id < 0 || id >= len(c.sysPool) {
		panic("Trying to release out of range syspool")
	}
	if c.sysPool[id].available != 0 {
		panic("Trying to release an available channel")
	}

	c.sl.Lock()
	c.sysPool[id].available = 0
	c.sl.Unlock()
}

func (c *CooperativeRuntime) SysSend(id int, r OcallRes) {
	c.sysPool[id].c <- r
}

func (c *CooperativeRuntime) AcquireAllocPool() (int, chan *AllocAttr) {
	c.sl.Lock()
	for i, s := range c.allocPool {
		if s.available == 1 {
			c.allocPool[i].available = 0
			c.allocPool[i].id = i
			c.sl.Unlock()
			return i, c.allocPool[i].c
		}
	}
	c.sl.Unlock()
	panic("Ran out of allocpool channels.")
	return -1, nil
}

func (c *CooperativeRuntime) ReleaseAllocPool(id int) {
	if id < 0 || id >= len(c.allocPool) {
		panic("Trying to release out of range syspool")
	}
	if c.allocPool[id].available != 0 {
		panic("Trying to release an available channel")
	}

	c.sl.Lock()
	c.allocPool[id].available = 0
	c.sl.Unlock()
}

func (c *CooperativeRuntime) AllocSend(id int, r *AllocAttr) {
	c.allocPool[id].c <- r
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
	Cooprt.Ocall = make(chan OcallReq)
	Cooprt.OAllocReq = make(chan AllocAttr)
	Cooprt.sl = &secspinlock{0}
	for i := range Cooprt.pool {
		Cooprt.pool[i] = &poolSudog{&sudog{}, false, 1}
		Cooprt.pool[i].wg.id = int32(i)
	}

	for i := range Cooprt.sysPool {
		Cooprt.sysPool[i] = &poolSysChan{i, 1, make(chan OcallRes)}
	}

	for i := range Cooprt.allocPool {
		Cooprt.allocPool[i] = &poolAllocChan{i, 1, make(chan *AllocAttr)}
	}

	buffstart := unsafe.Pointer(membufaddr)
	p, err := mmap(buffstart, POOLMEM, _PROT_READ|_PROT_WRITE, _MAP_FIXED|_MAP_ANON|_MAP_PRIVATE, -1, 0)
	if err != 0 || uintptr(p) != membufaddr {
		throw("Unable to mmap memory pool for the enclave.")
	}
	Cooprt.mmStart = uintptr(p)
	Cooprt.currHead = uintptr(p)

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

// TODO @aghosn To remove
func GetIsEnclave() bool {
	return isEnclave
}

// Functions and datastructures used during the runtime init.

// Addresses that we need to allocate before hand.
type Relocation struct {
	Addr uintptr
	Size uintptr
}

var (
	//sgxPreallocated = [2]uintptr{0x1C000000000, 0x1C420000000}
	//Previous 0xC000000000 0xC41FFF8000
	EnclavePreallocated = map[uintptr]Relocation{
		0xC000000000: Relocation{(0xC00000000 + ENCLMASK), 0x1000},
		0xC41FFF8000: Relocation{(0xC00000000 + 0x1000*2 + ENCLMASK), 0x108000},
	}

	relocKey = [2]uintptr{0xC000000000, 0xC41FFF8000}
	relocVal = [2]uintptr{0xC00000000 + ENCLMASK, 0xC00000000 + 0x1000*2 + ENCLMASK}
	relocSiz = [2]uintptr{0x1000, 0x108000}

	membufaddr = uintptr(0xC00000000 + ENCLMASK + 0x010000000)
)

// enclaveTransPrealloc checks if a given address was preallocated for the runtime.
// It is used to avoid calling mmap during the runtime initialization.
// It returns a boolean and the corresponding address.
// You can see it as a level of indirection that relocates the mmap regions
// at runtime. At this time, the allocation of a map is not possible.
// As a result, we have to duplicate the map that we have above.
func enclaveTransPrealloc(n uintptr) (uintptr, bool) {
	for idx, val := range relocKey {
		if n == val {
			return relocVal[idx], (isEnclave && true)
		}

		if n >= val && n < val+relocSiz[idx] {
			reloc := relocVal[idx] + (n - val)
			return reloc, (isEnclave && true)
		}
	}

	print("\nUnable to find a relocation\n")
	return uintptr(0), false
}

func enclaveIsMapped(ptr uintptr, n uintptr) bool {
	for idx, val := range relocVal {
		if ptr >= val && ptr+n <= val+relocSiz[idx] {
			return true
		}
	}

	return false
}