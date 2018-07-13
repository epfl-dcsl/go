package gosec

import (
	"debug/elf"
	"log"
	"os"
	"reflect"
	"runtime"
	"sort"
	"syscall"
	"unsafe"
)

const (
	SGX_PATH = "/dev/isgx"
	PSIZE    = uintptr(0x1000)
	//TODO @aghosn this must be exactly the same as in amd64/obj.go
	ENCLMASK = 0x040000000000
	ENCLSIZE = 0x001000000000

	MMMASK = 0x050000000000
)

type SortedElfSections []*elf.Section

func (s SortedElfSections) Len() int {
	return len(s)
}

func (s SortedElfSections) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortedElfSections) Less(i, j int) bool {
	return s[i].Addr < s[j].Addr
}

var (
	sgxFd *os.File = nil
)

// asm_eenter calls the enclu.
func asm_eenter(tcs, xcpt, rdi, rsi uint64)

// asm_exception does an eresume
func asm_exception()

func sgxLoadProgram(path string) {
	sgxInit()
	file, err := elf.Open(path)
	check(err)
	//defer func() { check(file.Close()) }()

	secs, wrap := sgxCreateSecs(file)

	// ECREATE & mmap enclave
	sgxEcreate(secs)

	// Allocate the equivalent region for the eadd page.
	srcRegion := &sgx_wrapper{transposeOut(wrap.base), wrap.siz,
		transposeOut(wrap.stack), wrap.ssiz, transposeOut(wrap.tcs), nil}

	src := srcRegion.base
	prot := int(_PROT_READ | _PROT_WRITE)
	srcptr, ret := syscall.RMmap(src, int(srcRegion.siz), prot,
		_MAP_NORESERVE|_MAP_ANON|_MAP_FIXED|_MAP_PRIVATE, -1, 0)
	check(ret)
	srcRegion.alloc = srcptr

	// Check that the sections are sorted now.
	sort.Sort(SortedElfSections(file.Sections))

	// EADD the different parts, mmap them at different offsets.
	var aggreg []*elf.Section
	for _, sec := range file.Sections {
		if sec.Flags&elf.SHF_ALLOC != elf.SHF_ALLOC {
			continue
		}
		if len(aggreg) == 0 || aggreg[len(aggreg)-1].Flags == sec.Flags {
			aggreg = append(aggreg, sec)
			continue
		}

		sgxMapSections(secs, aggreg, wrap, srcRegion)
		aggreg = nil
		aggreg = append(aggreg, sec)
	}
	sgxMapSections(secs, aggreg, wrap, srcRegion)

	//Setup the stack arguments and Cooprt.
	pstack := runtime.SetupEnclSysStack(srcRegion.stack + srcRegion.ssiz)

	// Mprotect and EADD stack and preallocated.
	sgxStackPreallocEadd(secs, wrap, srcRegion)
	sgxInitEaddTCS(file.Entry, secs, wrap, srcRegion)

	// EINIT: first get the token, then call the ioctl.
	sgxHashFinalize()
	tok := sgxTokenGetAesm(secs)
	sgxEinit(secs, &tok)

	//TODO for debugging
	//	base := uintptr(0x40000001000)
	//	base2 := base - ENCLMASK + MMMASK
	//	for i := uintptr(0); i < PSIZE; i++ {
	//		b := (*byte)(unsafe.Pointer(base + i))
	//		b2 := (*byte)(unsafe.Pointer(base2 + i))
	//		log.Println("A byte: ", *b, "---> ", *b2)
	//
	//	}

	//unmap the srcRegion
	err = syscall.Munmap(srcptr)
	check(err)

	transpstack := transposeIn(pstack)

	sgxEEnter(uint64(wrap.tcs), uint64(transpstack))
}

//TODO remove this is just to try to create an enclave.
func SGXFull() {
	sgxInit()
	//addr := uintptr(0x040000000000)
	addr := uintptr(ENCLMASK)
	//siz := uintptr(0x001000000000)
	siz := uintptr(0x8000)
	prot := int32(_PROT_READ | _PROT_WRITE | _PROT_EXEC)
	ptr, err := runtime.RMmap(unsafe.Pointer(addr), siz, prot, _MAP_SHARED, int32(sgxFd.Fd()), 0)
	if err != 0 || addr != uintptr(ptr) {
		log.Fatalln("Unable to mmap the original page: ", err)
	}

	// Allocate the transposed region.
	srcReg, ers := syscall.RMmap(transposeOut(addr), int(siz), _PROT_READ|_PROT_WRITE|_PROT_EXEC,
		_MAP_ANON|_MAP_FIXED|_MAP_PRIVATE|_MAP_NORESERVE, -1, 0)
	check(ers)

	// Fill the region with 42.
	for i := 0; i < len(srcReg); i++ {
		srcReg[i] = byte(42)
	}

	secs := &secs_t{}
	secs.size = uint64(siz) //uint64(siz)
	secs.baseAddr = uint64(addr)
	secs.xfrm = 0x7
	secs.ssaFrameSize = 1
	secs.attributes = 0x06

	sgxHashEcreate(secs)

	// ECREATE
	parms := &sgx_enclave_create{}
	parms.src = uint64(uintptr(unsafe.Pointer(secs)))
	ptr2 := uintptr(unsafe.Pointer(parms))
	_, _, ret := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_CREATE), ptr2)
	if ret != 0 {
		log.Fatalln("Failed in call to ecreate: ", ret)
	}

	// EADD all the pages.
	sgxAddRegion(secs, addr, transposeOut(addr), siz-PSIZE, uintptr(prot), SGX_SECINFO_REG)

	// EADD the TCS
	log.Println("The size of the tcs struct ", unsafe.Sizeof(tcs_t{}))
	sgxAddRegion(secs, addr+siz-PSIZE, transposeOut(addr+siz-PSIZE), PSIZE, uintptr(_PROT_NONE), SGX_SECINFO_TCS)

	// Get the token.
	sgxHashFinalize()
	tok := sgxTokenGetAesm(secs)
	sgxEinit(secs, &tok)
	panic("Dead")
}

// palign does a page align.
// If lower is true, it takes the lower address to start (align up)errno 0
// Otherwise it takes the greater page alignment address (align down)
func palign(addr uint64, lower bool) uint64 {
	const mask = uint64(0xFFFFFFFFFFFFF000)
	res := addr & mask
	if res < addr && !lower {
		return res + uint64(PSIZE)
	}

	return res
}

// sgxCreateSecs generates the SGX SECS struct according to the file.
// It goes through the elf and computes the range of addresses needed for the
// enclave ELRANGE. That includes the heap and the system stack.
// It should not mmap anything. This will be done later on.
func sgxCreateSecs(file *elf.File) (*secs_t, *sgx_wrapper) {
	var aggreg []*elf.Section
	fnFilter := func(e *elf.Section) bool {
		return e.Flags&elf.SHF_ALLOC == elf.SHF_ALLOC
	}

	for _, sec := range file.Sections {
		if fnFilter(sec) {
			aggreg = append(aggreg, sec)
		}
	}

	var baseAddr = uint64(ENCLMASK * 2)
	var endAddr = uint64(0x0)
	for _, sec := range aggreg {
		if sec.Addr < baseAddr {
			baseAddr = sec.Addr
		}
		if sec.Addr+sec.Size > endAddr {
			endAddr = sec.Addr + sec.Size
		}
	}

	// We can create the bounds that we want for the enclave as long as it contains
	// the values from the binary.
	if baseAddr < ENCLMASK {
		log.Fatalf("gosec: < binary outside of enclave region: %x\n", baseAddr)
	}

	if endAddr > ENCLMASK+ENCLSIZE {
		log.Fatalf("gosec: > binary outside of enclave region: %x\n", endAddr)
	}

	secs := &secs_t{}
	secs.baseAddr = uint64(ENCLMASK)
	secs.size = uint64(ENCLSIZE)
	secs.xfrm = 0x7
	secs.ssaFrameSize = 1
	secs.attributes = 0x06

	// Check the stack as well
	saddr := uintptr(palign(endAddr, false)) + 2*PSIZE
	ssize := int(0x8000)
	if saddr+uintptr(ssize) > ENCLMASK+ENCLSIZE {
		log.Fatalln("gosec: stack goes beyond enclave limits.")
	}

	//Check the tcs, ssa, etc..
	wrapper := &sgx_wrapper{uintptr(secs.baseAddr), uintptr(secs.size), saddr,
		uintptr(ssize), saddr + uintptr(ssize) + PSIZE, nil}

	if wrapper.tcs+TCS_OFF_END > ENCLMASK+ENCLSIZE {
		log.Fatalln("gosec: TCS is out of enclave limits.")
	}

	for _, v := range runtime.EnclavePreallocated {
		if v.Addr+v.Size > ENCLMASK+ENCLSIZE {
			log.Fatalf("gosec: > preallocation out of enclave boundaries: %x\n", v.Addr+v.Size)
		}
		if v.Addr < ENCLMASK {
			log.Fatalf("gosec: < preallocation out of enclave boundaries: %x\n", v.Addr)
		}
		if v.Addr > wrapper.tcs && v.Addr < wrapper.tcs+TCS_OFF_END {
			log.Fatalln("gosec: the tcs overlaps with preallocated.")
		}
	}

	return secs, wrapper
}

// TODO will need to allocate the TCS as well.
func sgxStackPreallocEadd(secs *secs_t, wrap, srcRegion *sgx_wrapper) {
	prot := uintptr(_PROT_READ | _PROT_WRITE)
	log.Printf("The stack address is %x\n", wrap.stack)

	sgxAddRegion(secs, wrap.stack, srcRegion.stack, wrap.ssiz, prot, SGX_SECINFO_REG)

	for _, v := range runtime.EnclavePreallocated {
		_, _, err := syscall.Syscall(syscall.SYS_MPROTECT, v.Addr, v.Size, prot)
		if err != 0 {
			log.Fatalf("gosec: unable to mprotect %x, size %x, %v\n", v.Addr, v.Size, err)
		}
		sgxAddRegion(secs, v.Addr, transposeOut(v.Addr), v.Size, prot, SGX_SECINFO_REG)
	}
}

// TODO should maybe change the layout.
func sgxInitEaddTCS(entry uint64, secs *secs_t, wrap, srcRegion *sgx_wrapper) {
	log.Printf("The entry %x\n", entry)
	tcs := (*tcs_t)(unsafe.Pointer(srcRegion.tcs))
	tcs.reserved1 = uint64(0)
	tcs.flags = uint64(0)
	tcs.ossa = uint64(wrap.tcs+TCS_OFF_SSA) - secs.baseAddr
	tcs.cssa = uint32(0)
	tcs.nssa = TCS_N_SSA
	tcs.oentry = entry - secs.baseAddr
	tcs.reserved2 = uint64(0)
	tcs.ofsbasgx = uint64(wrap.tcs+TCS_OFF_FS) - secs.baseAddr
	tcs.ogsbasgx = uint64(wrap.tcs+TCS_OFF_GS) - secs.baseAddr
	tcs.fslimit = SGX_FS_LIMIT
	tcs.gslimit = SGX_GS_LIMIT
	for i := range tcs.reserved3 {
		tcs.reserved3[i] = uint64(0)
	}

	// Add the TCS
	sgxAddRegion(secs, wrap.tcs, srcRegion.tcs, PSIZE, _PROT_READ|_PROT_WRITE, SGX_SECINFO_TCS)

	// Add the SSA and FS.
	sgxAddRegion(secs, wrap.tcs+TCS_OFF_SSA, srcRegion.tcs+TCS_OFF_SSA,
		TCS_OFF_END-TCS_OFF_SSA, _PROT_READ|_PROT_WRITE, SGX_SECINFO_REG)
}

func sgxAddRegion(secs *secs_t, addr, src, siz, prot uintptr, tpe uint64) {
	// First do the mprotect.
	_, _, ret := syscall.Syscall(syscall.SYS_MPROTECT, addr, siz, prot)
	if ret != 0 {
		log.Println("gosec: sgxAddRegion mprotect failed ", ret)
		panic("stopping execution.")
	}
	for x, y := addr, src; x < addr+siz; x, y = x+PSIZE, y+PSIZE {
		sgxEadd(secs, x, y, prot, tpe)
	}
}

func transposeOut(addr uintptr) uintptr {
	if addr < ENCLMASK || addr > ENCLMASK+ENCLSIZE {
		log.Fatalln("gosec: transpose out invalid address: ", addr)
	}
	return (addr - ENCLMASK + MMMASK)
}

func transposeIn(addr uintptr) uintptr {
	if addr < MMMASK || addr > MMMASK+ENCLSIZE {
		log.Fatalln("gosec: transpose in invalid address: ", addr)
	}
	return (addr - MMMASK + ENCLMASK)
}

func sgxMapSections(sgxsec *secs_t, secs []*elf.Section, wrap, srcRegion *sgx_wrapper) {
	if len(secs) == 0 {
		return
	}

	start := uintptr(palign(uint64(secs[0].Addr), true))
	end := uintptr(palign(uint64(secs[len(secs)-1].Addr+secs[len(secs)-1].Size), false))
	size := int(end - start)
	if start >= end {
		log.Fatalf("Error, sections are not ordered: %#x - %#x", start, end)
	}
	if start < wrap.base || end > wrap.base+wrap.siz {
		panic("gosec: section is outside of the enclave region.")
	}

	for _, sec := range secs {
		if sec.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := sec.Data()
		check(err)
		offset := int(sec.Addr - uint64(wrap.base))
		for i := range data {
			srcRegion.alloc[offset+i] = data[i]
		}
	}
	prot := _PROT_READ
	if (secs[0].Flags & elf.SHF_WRITE) == elf.SHF_WRITE {
		prot |= _PROT_WRITE
	}

	if (secs[0].Flags & elf.SHF_EXECINSTR) == elf.SHF_EXECINSTR {
		prot |= _PROT_EXEC
	}

	sgxAddRegion(sgxsec, start, transposeOut(start), uintptr(size), uintptr(prot), SGX_SECINFO_REG)
}

func sgxInit() int {
	if sgxFd != nil {
		return 0
	}
	var err error
	sgxFd, err = os.OpenFile(SGX_PATH, os.O_RDWR, 0)
	check(err)
	// Initialize the signature.
	sgxHashInit()
	return 0
}

// sgxEcreate calls the IOCTL to create the enclave.
// It first performs an mmap of the entire region that we use for the enclave.
func sgxEcreate(secs *secs_t) {
	prot := int32(_PROT_NONE)
	mprot := int32(_MAP_SHARED | _MAP_FIXED)
	fd := int32(sgxFd.Fd())
	addr := uintptr(secs.baseAddr)
	ptr, err := runtime.RMmap(unsafe.Pointer(addr), uintptr(secs.size), prot, mprot, fd, 0)
	if err != 0 || addr != uintptr(ptr) {
		log.Fatalln("gosec: unable to mmap the enclave: ", err)
	}

	parms := &sgx_enclave_create{}
	parms.src = uint64(uintptr(unsafe.Pointer(secs)))
	ptr2 := uintptr(unsafe.Pointer(parms))
	_, _, ret := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_CREATE), ptr2)
	if ret != 0 {
		log.Println("The secs: ", secs)
		log.Fatalln("Failed in call to ecreate: ", ret)
	}

	sgxHashEcreate(secs)
}

func sgxEadd(secs *secs_t, daddr, oaddr, prot uintptr, tpe uint64) {
	eadd := &sgx_enclave_add_page{}
	eadd.addr = uint64(daddr)
	eadd.src = uint64(uintptr(oaddr))
	eadd.mrmask = uint16(0xffff)
	if prot&_PROT_WRITE != 0 && tpe != SGX_SECINFO_TCS {
		eadd.mrmask = uint16(0x0)
	}

	secinfo := &isgx_secinfo{}
	secinfo.flags = tpe
	if prot&_PROT_EXEC != 0 {
		secinfo.flags |= SGX_SECINFO_X
	}
	if prot&_PROT_READ != 0 {
		secinfo.flags |= SGX_SECINFO_R
	}
	if prot&_PROT_WRITE != 0 {
		secinfo.flags |= SGX_SECINFO_W
	}

	// Special case for the TCS, no protections.
	if tpe == SGX_SECINFO_TCS {
		secinfo.flags = SGX_SECINFO_TCS
	}
	eadd.secinfo = uint64(uintptr(unsafe.Pointer(secinfo)))
	_, _, ret := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_ADD_PAGE), uintptr(unsafe.Pointer(eadd)))
	if ret != 0 {
		log.Println("Unable to add a page: ", daddr)
		panic("Stopping execution before adding a page.")
	}

	// Add it to the hash.
	sgxHashEadd(secs, secinfo, daddr)
}

func sgxEinit(secs *secs_t, tok *TokenGob) {
	parm := &sgx_enclave_init{}
	parm.addr = secs.baseAddr

	//Create the proper size for enclave css.
	signature := &tok.Meta.Enclave_css //&flat_enclave_css_t{}
	if unsafe.Sizeof(*signature) != uintptr(1808) {
		panic("gosec: the enclave_css is not the proper size.")
	}

	parm.sigstruct = uint64(uintptr(unsafe.Pointer(signature)))
	parm.einittoken = uint64(uintptr(unsafe.Pointer(&tok.Token[0])))

	ptr := uintptr(unsafe.Pointer(parm))
	p1, _, ret := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_INIT), ptr)

	if ret != 0 || p1 != 0 {
		log.Println("gosec: sgxEinit failed with return code ", ret, "-- p1: ", p1)
		panic("Stopping the execution before performing einit.")
	}
}

func sgxEEnter(tcs uint64, pstack uint64) {
	//TODO SETUP a new fucking stack here.
	rdi, rsi := uint64(0), uint64(0)
	prot := _PROT_READ | _PROT_WRITE
	ssiz := int(0x8000)
	_, err := syscall.RMmap(MMMASK, ssiz, prot, _MAP_PRIVATE|_MAP_ANON|_MAP_FIXED, -1, 0)
	check(err)

	// Set up the stack arguments.
	// RSP 32
	addrpstack := uintptr(MMMASK) + uintptr(ssiz) - unsafe.Sizeof(tcs)
	ptr := (*uint64)(unsafe.Pointer(addrpstack))
	*ptr = pstack

	// RSP 24
	addrsi := addrpstack - unsafe.Sizeof(tcs)
	ptr = (*uint64)(unsafe.Pointer(addrsi))
	*ptr = uint64(uintptr(unsafe.Pointer(&rsi)))

	// RSP 16
	addrdi := addrsi - unsafe.Sizeof(tcs)
	ptr = (*uint64)(unsafe.Pointer(addrdi))
	*ptr = uint64(uintptr(unsafe.Pointer(&rdi)))

	// RSP 8
	xcpt := uint64(reflect.ValueOf(asm_exception).Pointer())
	addrxcpt := addrdi - unsafe.Sizeof(tcs)
	ptr = (*uint64)(unsafe.Pointer(addrxcpt))
	*ptr = xcpt

	// RPS 0
	addrtcs := addrxcpt - unsafe.Sizeof(tcs)
	ptr = (*uint64)(unsafe.Pointer(addrtcs))
	*ptr = tcs

	fn := unsafe.Pointer(reflect.ValueOf(asm_eenter).Pointer())

	log.Printf("Gonna jump to address %x, tcs is %x, pstack %x\n", uintptr(fn), tcs, pstack)

	runtime.StartEnclaveOSThread(addrtcs, fn)
	log.Println("After the run")
	for {
	}
}

func testEntry() {
	log.Println("Test and I am here")
}

func sgxException() {
	log.Fatalln("SGX exception occured.")
}
