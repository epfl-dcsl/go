package runtime

import (
	"unsafe"
)

//EcallServerRequest type is used to send a request for the enclave to spawn
//a new dedicated ecall server listening on the provided private PC channel.
type EcallServerReq struct {
	PrivChan chan EcallReq
}

//EcallReq contains the arguments for an ecall. Mimics the newproc interface.
//Name is the target routine's name.
//Siz is the size of the argument buffer.
//Argp all the arguments.
//Buf an extra slice buffer.
type EcallReq struct {
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

type AllocReq struct {
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
	c         chan *AllocReq
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
	EcallSrv  chan EcallServerReq
	Ocall  chan OcallReq
	OAlloc chan AllocReq

	argc int32
	argv **byte

	readyE lfqueue //Ready to be rescheduled in the enclave
	readyO lfqueue //Ready to be rescheduled outside of the enclave

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

	POOL_INIT_SIZE = 5000 //Default size for the pools.

	// TODO this must be the same as in the gosec package.
	// Later move all of these within a separate package and share it.
	MEMBUF_START = (ENCLMASK + ENCLSIZE - PSIZE - MEMBUF_SIZE)
)

func InitCooperativeRuntime() {
	if Cooprt != nil {
		return
	}

	Cooprt = &CooperativeRuntime{}
	Cooprt.EcallSrv, Cooprt.argc, Cooprt.argv = make(chan EcallServerReq), -1, argv
	Cooprt.Ocall = make(chan OcallReq)
	Cooprt.OAlloc = make(chan AllocReq)

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
		Cooprt.allocPool[i] = &poolAllocChan{i, 1, make(chan *AllocReq)}
	}

	Cooprt.membuf_head = uintptr(MEMBUF_START)

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

//MarkNoFutex sets the g's markednofutex attribute to true.
//This prevents blocking on a channel operation.
func MarkNoFutex() {
	_g_ := getg()
	_g_.markednofutex = true
}

//MarkFutex sets the g's markednofutex to false.
//This allows the routine to futex sleep on a lock.
func MarkFutex() {
	_g_ := getg()
	_g_.markednofutex = false
}

//IsEnclave exposes the runtime.isEnclave value to the outside.
func IsEnclave() bool {
	return isEnclave
}

//IsSimulation exposes the runtime.isSimulation to the outside.
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

//AvoidDeadlock drives the scheduler forever.
func AvoidDeadlock() {
	for {
		//if isEnclave {
			Gosched()
		//} else {
		//	usleep(1000)
		//	Gosched()
		//}

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
// them in the local or global run queue.
// the locked argument tells us if sched.lock is locked.
func migrateCrossDomain(locked bool) {
	if cprtQ == nil {
		throw("migrateCrossdomain called on un-init cprtQ.")
	}

	sgq, tail, size := lfqget(cprtQ, locked)
	if size == 0 {
		return
	}
	if sgq == nil {
		println("Oh mighty fucks: ", size)
		throw("Crashy crash")
	}
	for i := 0; i < size; i++ {
		sg := sgq
		gp := sg.g
		if sgq.schednext != 0 {
			sgq = sgq.schednext.ptr()
		} else if sgq != tail {
			throw("malformed sgqueue, tail does not match tail(q)")
		}
		sg.schednext = 0
		ready(gp, 3+1, false)
	}
	_g_ := getg()
	if size > 0 && _g_.m.spinning {
		resetspinning()
	}
}

func acquireSudogFromPool(elem unsafe.Pointer, isrcv bool, size uint16) (*sudog, unsafe.Pointer) {
	if !isEnclave {
		panicGosec("Acquiring fake sudog from non-trusted domain.")
	}
	if size > SG_BUF_SIZE {
		panic("fake sudog buffer is too small.")
	}
	for i := range Cooprt.pool {
		if Cooprt.pool[i].available == 1 {
			Cooprt.pool[i].available = 0
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
	Cooprt.pool[sg.id].available = 1
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
// This method should be called only once the isReschedulable returned false.
func (c *CooperativeRuntime) crossGoready(sg *sudog) {
	// We are about to make ready a sudog that is not from the pool.
	// This can happen only when non-trusted has blocked on a channel.
	target := &c.readyE
	if sg.id == -1 {
		if sg.g.isencl || sg.g.isencl == isEnclave {
			panicGosec("Misspredicted the crossdomain scenario.")
		}
		target = &c.readyO
	}

	lfqput(target, sg)
}

func (c *CooperativeRuntime) AcquireSysPool() (int, chan OcallRes) {
	for i, s := range c.sysPool {
		if s.available == 1 {
			c.sysPool[i].available = 0
			c.sysPool[i].id = i
			return i, c.sysPool[i].c
		}
	}
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

	//TODO @aghosn make this atomic.
	c.sysPool[id].available = 1
}

func (c *CooperativeRuntime) SysSend(id int, r OcallRes) {
	c.sysPool[id].c <- r
}

func (c *CooperativeRuntime) AcquireAllocPool() (int, chan *AllocReq) {
	for i, s := range c.allocPool {
		if s.available == 1 {
			c.allocPool[i].available = 0
			c.allocPool[i].id = i
			return i, c.allocPool[i].c
		}
	}
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
	c.allocPool[id].available = 1
}

func (c *CooperativeRuntime) AllocSend(id int, r *AllocReq) {
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
}

func Newproc(ptr uintptr, argp *uint8, siz int32) {
	if Cooprt == nil {
		panic("Cooprt must be init before calling gosec.go:Newproc")
	}
	fn := &funcval{ptr}
	pc := getcallerpc()
	systemstack(func() {
		newproc1(fn, argp, siz, pc)
	})
}

//GosecureSend sends an ecall request on the p's private channel.
//TODO @aghosn: Maybe should change to avoid performing several copies!
func GosecureSend(req EcallReq) {
	gp := getg()
	if gp == nil {
		throw("Gosecure: un-init g.")
	}

	if Cooprt == nil {
		throw("Cooprt not initialized.")
	}
	if gp.ecallchan == nil {
		gp.ecallchan = make(chan EcallReq)
		srvreq := EcallServerReq{gp.ecallchan}
		MarkNoFutex()
		Cooprt.EcallSrv <- srvreq
		MarkFutex()
	}
	MarkNoFutex()
	gp.ecallchan <- req
	MarkFutex()
}

//go:noescape
func sched_setaffinity(pid, len uintptr, buf *uintptr) int32

func enclaveIsMapped(ptr uintptr, n uintptr) bool {
	if ptr >= Cooprt.eHeap && ptr+n <= Cooprt.eHeap+_MaxMemEncl {
		return true
	}
	return false
}

func EnclHeapSizeToAllocate() uintptr {
	return _MaxMemEncl
}
