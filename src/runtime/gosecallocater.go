package runtime

import (
	"unsafe"
)

//TODO rewrite to be write barrier compatible.
const (
	_psize          = 0x1000
	_uspgranularity = 64 //allocate by chunks of 64 bytes.
	_uspfree        = uint64(0x0000000000000000)
	_uspfull        = uint64(0xffffffffffffffff)
)

//uspan is an unsafe span of memory from which we perform the allocation.
//it corresponds to a page size.
type uspan struct {
	id       uint32
	bitmask  uint64              //quick check for available 64 bytes slots, bit 0 is [start;start+64[
	start    uintptr             //address of the beginning.
	freesize uintptr             //in bytes
	malloced map[uintptr]umentry //map from pointer to size.
}

type umentry struct {
	size uint32
	mask uint64
}

type sgentry struct {
	sg    *sudog
	isrcv bool
	orig  unsafe.Pointer
	buff  unsafe.Pointer
}

type uledger struct {
	start     uintptr
	size      uintptr
	allspans  []uspan
	freespans []*uspan
	fullspans []*uspan

	inusesg map[uintptr]sgentry //map that keeps track of untrusted sudog
	poolsg  []*sudog            //keep a pool of allocated sgs
	inited  bool
}

//initialize takes the start and size (in bytes) of the unsafe memory pool.
func (u *uledger) Initialize(start, size uintptr) {
	if size == 0 || size%_psize != 0 {
		throw("uledger: bad init values")
	}
	u.start = start
	u.size = size
	nbpages := size / _psize
	u.allspans = make([]uspan, nbpages)
	u.inusesg = make(map[uintptr]sgentry)
	for i := 0; i < int(nbpages); i++ {
		sp := &u.allspans[i]
		sp.id = uint32(i)
		sp.bitmask = _uspfree
		sp.start = start + uintptr(i)*_psize
		sp.freesize = _psize
		sp.malloced = make(map[uintptr]umentry)
		u.freespans = append(u.freespans, sp)
	}
}

func (u *uledger) Malloc(size uintptr) uintptr {
	if len(u.freespans) == 0 {
		println("Size of allspans ", len(u.allspans), ", full ", len(u.fullspans))
		println("Size of a sudog ", unsafe.Sizeof(sudog{}), " - ", u.inited)
		throw("uledger: ran out of memory")
	}
	for i := 0; i < len(u.freespans); i++ {
		if u.freespans[i].freesize >= size {
			//We are looking for contiguous space so it might fail
			if ptr, ok := u.freespans[i].allocate(size); ok {
				//If now the span is full, move it
				if u.freespans[i].freesize == 0 {
					span := u.freespans[i]
					u.freespans = append(u.freespans[:i], u.freespans[i+1:]...)
					u.fullspans = append(u.fullspans, span)
				}
				return ptr
			}
		}
	}
	throw("uledger: ran out of contiguous memory")
	return uintptr(0)
}

func (u *uledger) Free(ptr uintptr) {
	index := (ptr - u.start) / _psize //find the pod
	move, ok := u.allspans[index].deallocate(ptr)
	if !ok { //Failed de-allocating
		throw("uledger: error deallocating object!")
	}
	if move { //The span was full
		for i := 0; i < len(u.fullspans); i++ {
			if u.fullspans[i] == &u.allspans[index] {
				u.fullspans = append(u.fullspans[:i], u.fullspans[i+1:]...)
				u.freespans = append(u.freespans, &u.allspans[index])
				break
			}
		}
	}
}

//AllocateSudog allocates an unsafe sudog
func (u *uledger) AcquireUnsafeSudog(elem unsafe.Pointer, isrcv bool, size uint16) (*sudog, unsafe.Pointer) {
	if !isEnclave {
		panicGosec("Trying to allocate sudog from untrusted")
	}
	var sg *sudog
	if len(u.poolsg) > 0 {
		sg = u.poolsg[0]
		u.poolsg = u.poolsg[1:]
	} else {
		sg = (*sudog)(unsafe.Pointer(u.Malloc(unsafe.Sizeof(sudog{}))))
	}
	sg.id = 1
	buff := unsafe.Pointer(u.Malloc(uintptr(size)))
	if elem != nil {
		memmove(buff, elem, uintptr(size))
	}
	u.inusesg[uintptr(unsafe.Pointer(sg))] = sgentry{sg, isrcv, elem, buff}
	return sg, buff
}

//ReleaseUnsafeSudog
func (u *uledger) ReleaseUnsafeSudog(sg *sudog, size uint16) {
	if sg.id != -1 && !isEnclave {
		panicGosec("Wrong call to realeaseUnsafeSudog")
	}

	e, ok := u.inusesg[uintptr(unsafe.Pointer(sg))]
	if !ok {
		panicGosec("Cannot find the sudog in the inusesg map")
	}
	if e.isrcv && e.orig != nil {
		memmove(e.orig, e.buff, uintptr(size))
	}
	//Free the buffer
	u.Free(uintptr(e.buff))
	if len(u.poolsg) < 500 {
		u.poolsg = append(u.poolsg, sg)
		return
	}
	u.Free(uintptr(unsafe.Pointer(sg)))
}

func (u *uspan) allocate(size uintptr) (uintptr, bool) {
	cbits := size / _uspgranularity
	if size%_uspgranularity != 0 {
		cbits++
	}
	fcount := uintptr(0)
	mask := u.bitmask
	idx := -1
	for i := 0; i < 64 && idx == -1; i, mask = i+1, mask>>1 {
		if (mask & 1) == 0 {
			fcount++
			if fcount == cbits { //we can allocate!
				idx = i - int(cbits) + 1
			}
			continue
		}
		fcount = 0
	}
	if idx == -1 { //failure
		return 0, false
	}
	occupied := uint64(0)
	for i := 0; i < int(cbits); i++ {
		occupied |= 1 << uintptr(idx+i)
	}
	u.bitmask |= occupied
	ptr := u.start + uintptr(idx)*_uspgranularity
	u.malloced[ptr] = umentry{uint32(cbits * _uspgranularity), occupied}
	u.freesize -= cbits * _uspgranularity
	return ptr, true
}

func (u *uspan) deallocate(ptr uintptr) (bool, bool) {
	e, ok := u.malloced[ptr]
	if !ok {
		return false, false
	}
	delete(u.malloced, ptr)
	move := false
	if u.bitmask == _uspfull {
		move = true
	}
	u.bitmask ^= e.mask
	u.freesize += uintptr(e.size)
	return move, true
}
