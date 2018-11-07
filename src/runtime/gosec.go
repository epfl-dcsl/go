package runtime

import (
	"runtime/internal/atomic"
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
	available uint32
	buff      []byte
	orig      unsafe.Pointer
	isRcv     bool
}

type CooperativeRuntime struct {
	Ecall     chan EcallAttr
	Ocall     chan OcallReq
	OAllocReq chan AllocAttr

	argc int32
	argv **byte

	readyE sgqueue //Ready to be rescheduled in the enclave
	readyO sgqueue //Ready to be rescheduled outside of the enclave

	//pool of sudog structs allocated in non-trusted.
	sudogpool_lock secspinlock //lock for the pool of sudog
	pool           []*poolSudog

	//pool of answer channels.
	//syspool_lock   secspinlock // lock for pool syschan
	sysPool []*poolSysChan
	//allocpool_lock secspinlock
	allocPool []*poolAllocChan

	membuf_head uintptr

	// The enclave heap region.
	// This is the equivalent of my previous preallocated regions.
	// TODO secure it somehow.
	eHeap uintptr
}

const (
	IsSim = true
	//TODO @aghosn this must be exactly the same as in amd64/obj.go
	PSIZE       = 0x1000
	ENCLMASK    = 0x040000000000
	ENCLSIZE    = 0x001000000000
	MMMASK      = 0x050000000000
	MEMBUF_SIZE = uintptr(PSIZE * 1400)

	SG_BUF_SIZE = 100 // size in bytes

	POOL_INIT_SIZE = 500 //Default size for the pools.

	// TODO this must be the same as in the gosec package.
	// Later move all of these within a separate package and share it.
	MEMBUF_START = (ENCLMASK + ENCLSIZE - PSIZE - MEMBUF_SIZE)
)

func InitCooperativeRuntime() {
	if Cooprt != nil {
		return
	}

	Cooprt = &CooperativeRuntime{}
	Cooprt.Ecall, Cooprt.argc, Cooprt.argv = make(chan EcallAttr), -1, argv
	Cooprt.Ocall = make(chan OcallReq)
	Cooprt.OAllocReq = make(chan AllocAttr)

	Cooprt.pool = make([]*poolSudog, POOL_INIT_SIZE)
	for i := range Cooprt.pool {
		Cooprt.pool[i] = &poolSudog{&sudog{}, false, 1, make([]byte, SG_BUF_SIZE), nil, false}
		Cooprt.pool[i].wg.id = int32(i)
	}

	Cooprt.sysPool = make([]*poolSysChan, POOL_INIT_SIZE)
	for i := range Cooprt.sysPool {
		Cooprt.sysPool[i] = &poolSysChan{i, 1, make(chan OcallRes)}
	}

	Cooprt.allocPool = make([]*poolAllocChan, POOL_INIT_SIZE)
	for i := range Cooprt.allocPool {
		Cooprt.allocPool[i] = &poolAllocChan{i, 1, make(chan *AllocAttr)}
	}

	Cooprt.membuf_head = uintptr(MEMBUF_START)

	//TODO for debugging remove afterwards
	Cooprt.readyO.lock.id = 1
	Cooprt.readyE.lock.id = 2

	Cooprt.eHeap = 0
	cprtQ = &(Cooprt.readyO)
}

func (c *CooperativeRuntime) SetHeapValue(e uintptr) bool {
	if c.eHeap != 0 {
		return false
	}
	c.eHeap = e
	return true
}

func IsEnclave() bool {
	return isEnclave
}

func IsSimulation() bool {
	return isSimulation
}

func checkEnclaveBounds(addr uintptr) {
	if isEnclave {
		// Enclave has access to everything.
		return
	}
	if addr >= ENCLMASK && addr < ENCLMASK+ENCLSIZE {
		print("pre-panic: addr ", hex(addr), "\n")
		panic("runtime: illegal address used outside of the enclave.")
	}
}

func panicGosec(a string) {
	if isEnclave {
		marker := (*uint64)(unsafe.Pointer(uintptr(0x050000000000)))
		*marker = uint64(0x666)
	}
	panic(a)
}

func AvoidDeadlock() {
	for {
		Gosched()
		procyield(70)
	}
}

// sysFutex allows to do a wakeup call on a futex while going through the
// interposition mechanism.
func sysFutex(addr *uint32, cnt uint32) {
	syscid, csys := Cooprt.AcquireSysPool()
	sys_futex := uintptr(202)
	req := OcallReq{true, sys_futex, uintptr(unsafe.Pointer(addr)),
		uintptr(_FUTEX_WAKE), uintptr(cnt), 0, 0, 0, syscid}
	Cooprt.Ocall <- req
	_ = <-csys
	Cooprt.ReleaseSysPool(syscid)
	// TODO aghosn Don't care about the result for now
}

// checkinterdomain detects inter domain crossing and panics if foreign has
// higher protection than local. Returns true if local and foreign belong to
// different domains.
// This function is called when writting to a channel for example.
func checkinterdomain(rlocal, rforeign bool) bool {
	if !rlocal && rforeign {
		panicGosec("An untrusted routine is trying to access a trusted channel")
	}
	return rlocal != rforeign
}

// migrateCrossDomain takes ready routines from the cross domain queue and puts
// them in the global run queue.
func migrateCrossDomain(local bool) {
	if cprtQ == nil {
		throw("migrateCrossdomain called on un-init cprtQ.")
	}

	sgq, tail, size := sgqtrydrain(cprtQ)
	if size == 0 {
		return
	}
	if sgq == nil {
		println("Oh mighty fucks: ", size)
		throw("Crashy crash")
	}
	var head *g = nil
	var prev *g = nil
	for i := 0; i < size; i++ {
		sg := sgq
		gp := sg.g
		if head == nil {
			head = gp
		}
		if prev != nil {
			prev.schedlink.set(gp)
		}
		if sgq.schednext != 0 {
			sgq = sgq.schednext.ptr()
		} else if sgq != tail {
			throw("malformed sgqueue, tail does not match tail(q)")
		}
		prev = gp
		sg.schednext = 0
	}
	if prev != nil {
		prev.schedlink = 0
		if local {
			injectglistnolock(head)
		} else {
			injectglist(head)
		}
	}
}

func migratelocalqueue() {
	_g_ := getg()
	if _g_.m.p.ptr().migrateq.size == 0 {
		// Nothing to do.
		return
	}
	head, tail, size := sgqdrainnolock(&_g_.m.p.ptr().migrateq)
	if size == 0 {
		throw("local queue got emptied randomly.")
	}
	if isEnclave {
		sgqputbatch(&Cooprt.readyO, head, tail, int32(size))
		return
	}
	sgqputbatch(&Cooprt.readyE, head, tail, int32(size))
}

func Schedticks() uint32 {
	_g_ := getg()
	return _g_.m.p.ptr().schedtick
}

func CPRTQLocks() uint32 {
	if cprtQ == nil {
		return 0
	}
	res := cprtQ.lock.enclock + cprtQ.lock.nenclock
	return res
}

func StatsDebugging() (uint32, uint32) {
	return Schedticks(), CPRTQLocks()
}

func acquireSudogFromPool(elem unsafe.Pointer, isrcv bool, size uint16) (*sudog, unsafe.Pointer) {
	if !isEnclave {
		panicGosec("Acquiring fake sudog from non-trusted domain.")
	}
	if size > SG_BUF_SIZE {
		panic("fake sudog buffer is too small.")
	}
	for i := range Cooprt.pool {
		if atomic.Xchg(&Cooprt.pool[i].available, 0) == 1 {
			//Cooprt.pool[i].available = 0
			Cooprt.pool[i].wg.id = int32(i)
			Cooprt.pool[i].isencl = isEnclave
			Cooprt.pool[i].orig = elem
			Cooprt.pool[i].isRcv = isrcv
			ptr := unsafe.Pointer(&(Cooprt.pool[i].buff[0]))
			if elem != nil {
				memmove(ptr, elem, uintptr(size))
			}
			return Cooprt.pool[i].wg, ptr
		}
	}
	//TODO @aghosn should come up with something here.
	panicGosec("Ran out of sudog in the pool.")
	return nil, nil
}

// crossReleaseSudog calls the appropriate releaseSudog version depending on whether
// the sudog is a crossdomain one or not.
func crossReleaseSudog(sg *sudog, size uint16) {
	// Check if this is not from the pool and is same domain (regular path)
	if isReschedulable(sg) {
		releaseSudog(sg)
		return
	}

	// This is called from someone who just woke up.
	// We are executing and are in the correct domain.
	// Hence this is our first check: id != -1 implies we are in the enclave
	if sg.id != -1 && !isEnclave {
		panicGosec("We have a pool sudog containing a non enclave element.")
	}

	//Copy back the result.
	if Cooprt.pool[sg.id].isRcv && Cooprt.pool[sg.id].orig != nil {
		value := unsafe.Pointer(&Cooprt.pool[sg.id].buff[0])
		memmove(Cooprt.pool[sg.id].orig, value, uintptr(size))
	}

	// Second step is if we are from the pool (and we are inside the enclave),
	// We are runnable again. We just release the sudog from the pool.
	Cooprt.pool[sg.id].isencl = false
	Cooprt.pool[sg.id].orig = nil
	Cooprt.pool[sg.id].isRcv = false
	//TODO @aghosn Make this atomic
	atomic.Store(&Cooprt.pool[sg.id].available, 1)
}

// isReschedulable checks if a sudog can be directly rescheduled.
// For that, we require the sudog to not belong to the pool and for the unblocking
// routine to belong to the same domain as this sudog.
func isReschedulable(sg *sudog) bool {
	if sg == nil {
		panicGosec("Calling isReschedulable with nil sudog.")
	}
	return (sg.id == -1 && !checkinterdomain(isEnclave, sg.g.isencl))
}

// crossGoready takes a sudog and makes it ready to be rescheduled.
// It picks the proper ready queue for the sudog in the cooperative runtime.
// This method should be called only once the isReschedulable returned false.
func (c *CooperativeRuntime) crossGoready(sg *sudog) {
	// We are about to make ready a sudog that is not from the pool.
	// This can happen only when non-trusted has blocked on a channel.
	_g_ := getg()
	if sg.id == -1 {
		if sg.g.isencl || sg.g.isencl == isEnclave {
			panicGosec("Misspredicted the crossdomain scenario.")
		}
		//sgqput(&c.readyO, sg)
		//return
	}

	// We have a sudog from the pool.
	//sgqput(&c.readyE, sg)
	sgqputnolock(&_g_.m.p.ptr().migrateq, sg)
}

func (c *CooperativeRuntime) AcquireSysPool() (int, chan OcallRes) {
	//c.syspool_lock.Lock()
	for i, s := range c.sysPool {
		if s.available == 1 {
			c.sysPool[i].available = 0
			c.sysPool[i].id = i
			//c.syspool_lock.Unlock()
			return i, c.sysPool[i].c
		}
	}
	//c.syspool_lock.Unlock()
	panicGosec("Ran out of syspool channels.")
	return -1, nil
}

func (c *CooperativeRuntime) ReleaseSysPool(id int) {
	if id < 0 || id >= len(c.sysPool) {
		panicGosec("Trying to release out of range syspool")
	}
	if c.sysPool[id].available != 0 {
		panicGosec("Trying to release an available channel")
	}

	//c.syspool_lock.Lock()
	//TODO @aghosn make this atomic.
	c.sysPool[id].available = 1
	//c.syspool_lock.Unlock()
}

func (c *CooperativeRuntime) SysSend(id int, r OcallRes) {
	c.sysPool[id].c <- r
}

func (c *CooperativeRuntime) AcquireAllocPool() (int, chan *AllocAttr) {
	//c.allocpool_lock.Lock()
	for i, s := range c.allocPool {
		if s.available == 1 {
			c.allocPool[i].available = 0
			c.allocPool[i].id = i
			//c.allocpool_lock.Unlock()
			return i, c.allocPool[i].c
		}
	}
	//c.allocpool_lock.Unlock()
	panicGosec("Ran out of allocpool channels.")
	return -1, nil
}

func (c *CooperativeRuntime) ReleaseAllocPool(id int) {
	if id < 0 || id >= len(c.allocPool) {
		panicGosec("Trying to release out of range syspool")
	}
	if c.allocPool[id].available != 0 {
		panicGosec("Trying to release an available channel")
	}

	//c.allocpool_lock.Lock()
	c.allocPool[id].available = 1
	//c.allocpool_lock.Unlock()
}

func (c *CooperativeRuntime) AllocSend(id int, r *AllocAttr) {
	c.allocPool[id].c <- r
}

// Sets up the stack arguments and returns the beginning of the stack address.
func SetupEnclSysStack(stack, eS uintptr) uintptr {
	if isEnclave {
		panicGosec("Should not allocate enclave from the enclave.")
	}

	addrArgc := stack - unsafe.Sizeof(argc)
	addrArgv := addrArgc - unsafe.Sizeof(argv)

	ptrArgc := (*int32)(unsafe.Pointer(addrArgc))
	*ptrArgc = argc

	// Initialize the Cooprt
	Cooprt.SetHeapValue(eS)

	ptrArgv := (***byte)(unsafe.Pointer(addrArgv))
	*ptrArgv = (**byte)(unsafe.Pointer(Cooprt))

	return addrArgv
}

func StartEnclaveOSThread(stack uintptr, fn unsafe.Pointer) {
	ret := clone(cloneFlags, unsafe.Pointer(stack), nil, nil, fn)
	if ret < 0 {
		write(2, unsafe.Pointer(&failthreadcreate[0]), int32(len(failthreadcreate)))
		exit(1)
	}
}

func StartSimOSThread(stack uintptr, fn unsafe.Pointer, eS uintptr) {
	if isEnclave {
		panicGosec("Should not allocate enclave from the enclave.")
	}
	addrArgc := stack - unsafe.Sizeof(argc)
	addrArgv := addrArgc - unsafe.Sizeof(argv)

	ptrArgc := (*int32)(unsafe.Pointer(addrArgc))
	*ptrArgc = argc

	// Set heap in Cooprt
	Cooprt.SetHeapValue(eS)

	ptrArgv := (***byte)(unsafe.Pointer(addrArgv))
	*ptrArgv = (**byte)(unsafe.Pointer(Cooprt))

	// RSP 32
	ssiz := uintptr(0x8000)
	addrpstack := uintptr(MMMASK) + uintptr(ssiz) - unsafe.Sizeof(uint64(0))
	ptr := (*uint64)(unsafe.Pointer(addrpstack))
	*ptr = uint64(addrArgv)

	stk := addrpstack - 4*unsafe.Sizeof(uint64(0))

	ret := clone(cloneFlags, unsafe.Pointer(stk), nil, nil, fn)
	if ret < 0 {
		write(2, unsafe.Pointer(&failthreadcreate[0]), int32(len(failthreadcreate)))
		exit(1)
	}
	SchedSetAffinity(int(ret), 0xF-0x7)
}

func Newproc(ptr uintptr, argp *uint8, siz int32) {
	fn := &funcval{ptr}
	pc := getcallerpc()
	systemstack(func() {
		newproc1(fn, argp, siz, pc)
	})
}

//go:noescape
func sched_setaffinity(pid, len uintptr, buf *uintptr) int32

func SchedSetAffinity(pid, set int) {
	var buf [1]uintptr
	buf[0] = uintptr(set)
	r := sched_setaffinity(uintptr(pid), unsafe.Sizeof(buf), &buf[0])
	if r < 0 {
		panic("Could not set sched affinity")
	}
}

func SchedGetAffinity() []uintptr {
	res := make([]uintptr, 1)
	r := sched_getaffinity(0, unsafe.Sizeof(res), &res[0])
	if r < 0 {
		panic("Unable to get sched affinity")
	}
	return res
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

func enclaveIsMapped(ptr uintptr, n uintptr) bool {
	if ptr >= Cooprt.eHeap && ptr+n <= Cooprt.eHeap+_MaxMemEncl {
		return true
	}
	return false
}

func EnclHeapSizeToAllocate() uintptr {
	return _MaxMemEncl
}
