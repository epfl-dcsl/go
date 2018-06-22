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
	SGX_SSTACK     = uintptr(0xe41ffd8000)
	SGX_SSTACK_SIZ = int(0x8000)
	SGX_PATH       = "/dev/isgx"
	PSIZE          = uintptr(0x1000)
)

var (
	sgxFd *os.File = nil
)

func sgxLoadProgram(path string) {
	//TODO @aghosn ecreate the enclave first.
	//Func ecreate.
	//Maybe need to aggregate size etc. firs

	//TODO @aghosn get the token here.

	//TODO @aghosn do the einit.
	file, err := elf.Open(path)
	check(err)
	defer func() { check(file.Close()) }()
	var aggreg []*elf.Section
	for _, sec := range file.Sections {
		if sec.Flags&elf.SHF_ALLOC != elf.SHF_ALLOC {
			continue
		}
		if len(aggreg) == 0 || aggreg[len(aggreg)-1].Flags == sec.Flags {
			aggreg = append(aggreg, sec)
			continue
		}

		//TODO do an MMap for the section, then do the eadd.
		aggreg = nil
		aggreg = append(aggreg, sec)
	}
	//TODO do an MMap for the section, then do the eadd for aggreg again
	//prot := _PROT_READ | _PROT_WRITE
	addr := SGX_SSTACK
	size := SGX_SSTACK_SIZ
	//TODO map the stack inside the enclave.

	//TODO change that as well, we need to create thread, move to a function
	// that does the eenter.
	fn := unsafe.Pointer(uintptr(file.Entry))
	runtime.AllocateOSThreadEncl(addr+uintptr(size), fn)
}

//TODO remove this is just to try to create an enclave.
func SGXFull() {
	addr := uintptr(0x060000000000)
	siz := uintptr(0x100000)
	prot := int32(_PROT_NONE)
	ptr, err := runtime.RMmap(unsafe.Pointer(addr), siz, prot, _MAP_SHARED, int32(sgxFd.Fd()), 0)
	if err != 0 || addr != uintptr(ptr) {
		log.Fatalln("Unable to mmap the original page.")
	}

	secs := &secs_t{}
	secs.size = uint64(siz)
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
		log.Fatalln("Unable to call ecreate.")
	}

	// EADD
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
func sgxCreateSecs(file *elf.File) *secs_t {
	var aggreg []*elf.Section
	fnFilter := func(e *elf.Section) bool {
		return e.Flags&elf.SHF_ALLOC == elf.SHF_ALLOC
	}

	for _, sec := range file.Sections {
		if fnFilter(sec) {
			aggreg = append(aggreg, sec)
		}
	}

	var baseAddr = uint64(0xFFFFFFFF)
	var endAddr = uint64(0x00000000)
	for _, sec := range aggreg {
		if sec.Addr < baseAddr {
			baseAddr = sec.Addr
		}
		if sec.Addr+sec.Size > endAddr {
			endAddr = sec.Addr + sec.Size
		}
	}

	//TODO @aghosn now allocate the heap with its size,
	// and the system stack. Also need to keep track of it somehow.
	// Need to make it page aligned.
	sec := &secs_t{}
	sec.baseAddr = palign(baseAddr, true)
	sec.size = palign(endAddr-baseAddr, false)
	return sec
}

func sgxInit() int {
	if sgxFd != nil {
		return 0
	}
	var err error
	sgxFd, err = os.OpenFile(SGX_PATH, os.O_RDONLY, 0)
	check(err)
	return 0
}
