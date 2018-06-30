package gosec

import (
	"debug/elf"
	"log"
	"os"
	"runtime"
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

var (
	sgxFd *os.File = nil
)

func sgxLoadProgram(path string) {
	sgxInit()
	file, err := elf.Open(path)
	check(err)
	defer func() { check(file.Close()) }()

	secs, wrap := sgxCreateSecs(file)

	// ECREATE & mmap enclave
	sgxEcreate(secs)

	// Allocate the equivalent region for the eadd page.
	srcRegion := &sgx_wrapper{transposeOut(wrap.base), wrap.siz,
		transposeOut(wrap.stack), wrap.ssiz, nil}

	src := srcRegion.base
	prot := int(_PROT_READ | _PROT_WRITE)
	ptr, ret := syscall.RMmap(src, int(srcRegion.siz), prot,
		_MAP_NORESERVE|_MAP_ANON|_MAP_FIXED|_MAP_PRIVATE, -1, 0)
	check(ret)
	srcRegion.alloc = ptr

	// Mprotect and EADD stack and preallocated.
	sgxStackPreallocEadd(secs, wrap, srcRegion)

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

	// TODO @aghosn do the EINIT
	sgxHashFinalize()

	// TODO do the unmap of srcRegion

	panic("We STOP SHORT")
	////TODO change that as well, we need to create thread, move to a function
	//// that does the eenter.
	//fn := unsafe.Pointer(uintptr(file.Entry))
	//runtime.AllocateOSThreadEncl(wrap.stack+wrap.ssiz, fn)
}

//TODO remove this is just to try to create an enclave.
func SGXFull() {
	//addr := uintptr(0x040000000000)
	addr := uintptr(ENCLMASK)
	//siz := uintptr(0x001000000000)
	siz := uintptr(ENCLSIZE)
	prot := int32(_PROT_NONE)
	ptr, err := runtime.RMmap(unsafe.Pointer(addr), siz, prot, _MAP_SHARED, int32(sgxFd.Fd()), 0)
	if err != 0 || addr != uintptr(ptr) {
		log.Fatalln("Unable to mmap the original page: ", err)
	}

	secs := &secs_t{}
	secs.size = uint64(siz) //uint64(siz)
	secs.baseAddr = uint64(addr)
	secs.xfrm = 0x7
	secs.ssaFrameSize = 1
	secs.attributes = 0x04

	// ECREATE
	parms := &sgx_enclave_create{}
	parms.src = uint64(uintptr(unsafe.Pointer(secs)))
	ptr2 := uintptr(unsafe.Pointer(parms))
	_, _, ret := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_CREATE), ptr2)
	if ret != 0 {
		log.Fatalln("Failed in call to ecreate: ", ret)
	}

	// EADD
	addr = 0x040000172000
	siz = 0x8000
	_, _, ret = syscall.Syscall(syscall.SYS_MPROTECT, addr, siz, _PROT_READ)
	if ret != 0 {
		log.Fatalln("Unable to perform the mprotect.")
	}

	content, err := runtime.RMmap(nil, 0x1000, _PROT_READ|_PROT_WRITE, _MAP_ANON|_MAP_PRIVATE, -1, 0)
	if err != 0 {
		log.Fatalln("Unable to mmap the second page.")
	}
	memsetstruct(unsafe.Pointer(content), 2, 0x1000)
	eadd := &sgx_enclave_add_page{}
	eadd.addr = uint64(addr)
	eadd.src = uint64(uintptr(content))
	eadd.mrmask = uint16(0xfff)

	secinfo := &isgx_secinfo{}
	secinfo.flags = SGX_SECINFO_R | SGX_SECINFO_REG

	eadd.secinfo = uint64(uintptr(unsafe.Pointer(secinfo)))
	_, _, ret = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_ADD_PAGE), uintptr(unsafe.Pointer(eadd)))
	if ret != 0 {
		log.Fatalln("Unable to add a page.")
	}
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
	secs.attributes = 0x04

	// Check the stack as well
	saddr := uintptr(palign(endAddr, false)) + 2*PSIZE
	ssize := int(0x8000)
	if saddr+uintptr(ssize) > ENCLMASK+ENCLSIZE {
		log.Fatalln("gosec: stack goes beyond enclave limits.")
	}

	for _, v := range runtime.EnclavePreallocated {
		if v.Addr+v.Size > ENCLMASK+ENCLSIZE {
			log.Fatalf("gosec: > preallocation out of enclave boundaries: %x\n", v.Addr+v.Size)
		}
		if v.Addr < ENCLMASK {
			log.Fatalf("gosec: < preallocation out of enclave boundaries: %x\n", v.Addr)
		}
	}
	wrapper := &sgx_wrapper{uintptr(secs.baseAddr), uintptr(secs.size), saddr, uintptr(ssize), nil}
	return secs, wrapper
}

func sgxStackPreallocEadd(secs *secs_t, wrap, srcRegion *sgx_wrapper) {
	prot := uintptr(_PROT_READ | _PROT_WRITE)
	_, _, err := syscall.Syscall(syscall.SYS_MPROTECT, wrap.stack, wrap.ssiz, prot)
	if err != 0 {
		log.Fatalln("gosec: unable to mprotect the stack: ", err)
	}

	sgxAddRegion(secs, wrap.stack, srcRegion.stack, wrap.ssiz, prot)

	for _, v := range runtime.EnclavePreallocated {
		_, _, err := syscall.Syscall(syscall.SYS_MPROTECT, v.Addr, v.Size, prot)
		if err != 0 {
			log.Fatalf("gosec: unable to mprotect %x, size %x, %v\n", v.Addr, v.Size, err)
		}
		sgxAddRegion(secs, v.Addr, transposeOut(v.Addr), v.Size, prot)
	}
}

func sgxAddRegion(secs *secs_t, addr, src, siz, prot uintptr) {
	for x, y := addr, src; x < addr+siz; x, y = x+PSIZE, y+PSIZE {
		sgxEadd(secs, x, y, prot)
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

	sgxAddRegion(sgxsec, start, transposeOut(start), uintptr(size), uintptr(prot))
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

func sgxEadd(secs *secs_t, daddr, oaddr, prot uintptr) {
	eadd := &sgx_enclave_add_page{}
	eadd.addr = uint64(daddr)
	eadd.src = uint64(uintptr(oaddr))
	eadd.mrmask = uint16(0xfff)

	secinfo := &isgx_secinfo{}
	secinfo.flags = SGX_SECINFO_REG
	if prot&_PROT_EXEC != 0 {
		secinfo.flags |= SGX_SECINFO_X
	}
	if prot&_PROT_READ != 0 {
		secinfo.flags |= SGX_SECINFO_R
	}
	if prot&_PROT_WRITE != 0 {
		secinfo.flags |= SGX_SECINFO_W
	}
	eadd.secinfo = uint64(uintptr(unsafe.Pointer(secinfo)))
	_, _, ret := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxFd.Fd()), uintptr(SGX_IOC_ENCLAVE_ADD_PAGE), uintptr(unsafe.Pointer(eadd)))
	if ret != 0 {
		log.Println("Unable to add a page: ", daddr)
		panic("Shit")
	}

	// Add it to the hash.
	sgxHashEadd(secs, secinfo, daddr)
}
