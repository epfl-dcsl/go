package gosec

import (
	"crypto/sha256"
	"debug/elf"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	ubase                 uintptr             = 0
	heapSize              uint64              = 0
	ECREATE_NO_FIXED_ADDR                     = unsafe.Pointer(nil) // TODO(aghons) check that this is correct.
	sgxfd                 *os.File            = nil
	esize                 uint64              = 0
	threads               []*enclave_thread_t = nil
	tcsMax                int                 = 0
	fileName              string              = ""
)

func CreateEnclave(path, einitPath string) EnclaveId {
	fd, err := os.Open(path)
	check(err)
	defer func() { check(fd.Close()) }()

	sb, err := fd.Stat()
	check(err)

	p, errno := runtime.RMmap(unsafe.Pointer(uintptr(0)), uintptr(sb.Size()), _PROT_READ, _MAP_PRIVATE, int32(fd.Fd()), 0)
	if errno != 0 {
		panic("Unable to mmap from 0x0 for the enclave binary.")
	}

	fileName = path
	createEnclaveMem(uintptr(p), path, einitPath)
	runtime.RMunmap(p, uintptr(sb.Size()))

	return 0
}

func DestroyEnclave(enclave EnclaveId) {

}

func createEnclaveMem(p uintptr, file, einitPath string) uintptr {
	var t *einittoken_t = nil
	var s *sigstruct_t = nil
	var sb os.FileInfo = nil

	if einitPath != "" {
		fd, err := os.Open(einitPath)
		check(err)
		defer func() { check(fd.Close()) }()

		sb, err = fd.Stat()
		check(err)
		tt, errno := runtime.RMmap(unsafe.Pointer(uintptr(0)), uintptr(sb.Size()), _PROT_READ, _MAP_PRIVATE, int32(fd.Fd()), 0)
		if errno != 0 {
			log.Fatalf("Unable to mmap the enclave init token file., error code %v", errno)
		}
		t = (*einittoken_t)(unsafe.Pointer(tt))
	} else {
		tt := getSectionAddress(p, file, ".note.token")
		t = (*einittoken_t)(unsafe.Pointer(tt))
	}

	ss := getSectionAddress(p, file, ".note.sigstruct")
	s = (*sigstruct_t)(unsafe.Pointer(ss))
	if s == nil {
		panic("Enclave binary should have .note.sigstruct section. ")
	}

	enc := getEnclaveParms(p, file)
	ssaFrameSize := 1
	nssa := 2
	tcsp := int(enc.tcsn)
	heap, stack := enc.heap_size/0x1000, enc.stack_size/0x1000
	size := getEnclaveSize(heap, stack, tcsp, ssaFrameSize, nssa, getLoadableSize(p), 1)
	ubase = ecreate(size, ssaFrameSize, s, uintptr(0))
	heapSize = enc.heap_size
	processPages(p, ubase, heap, stack, tcsp, nssa, addPage)

	if i := einit(ubase, s, t); i != 0 {
		DestroyEnclave(EnclaveId(ubase))
		log.Fatalf("Error while initializing enclave error code %v", i)
	}

	if einitPath != "" {
		runtime.RMunmap(unsafe.Pointer(ubase), uintptr(sb.Size()))
	}
	//var buffer byte
	//for i := 0; i < tcsp; i++ {
	//	seWriteProcessMem(Threads + 8, &buffer, 1, 0)
	//}
	return ubase
}

func getSectionAddress(p uintptr, file, path string) uintptr {
	f, err := elf.Open(file)
	check(err)
	defer func() { check(f.Close()) }()

	section := f.Section(path)
	if section == nil {
		log.Fatalf("Elf file '%v' does not contain a section '%v'", file, path)
	}
	return p + uintptr(section.Offset)
}

func getEnclaveParms(p uintptr, file string) *enclave_parms_t {
	start := getSectionAddress(p, file, ".tdata")
	s := (*uint64)(unsafe.Pointer(start))
	for *s != 0xBAADF00DDEADBABE {
		start += unsafe.Sizeof(uint64(1))
		s = (*uint64)(unsafe.Pointer(start))
	}
	return (*enclave_parms_t)(unsafe.Pointer(s))
}

func getEnclaveSize(heap, stack uint64, tcsp, ssaFrameSize, nssa, code, tls int) uint64 {
	return heap + uint64(tcsp)*(1+stack+uint64(ssaFrameSize*nssa)+uint64(tls)) + uint64(code)
}

func ecreate(npages uint64, ssaSize int, sigstruct *sigstruct_t, baseaddr uintptr) uintptr {
	secs := secs_t{ssaFrameSize: uint32(ssaSize), size: getNextPower2(npages * 0x1000)}

	var ptr unsafe.Pointer = nil
	var flagsProt int32 = _PROT_READ | _PROT_WRITE | _PROT_EXEC
	var flagsMap int32 = _MAP_SHARED

	if unsafe.Pointer(baseaddr) != ECREATE_NO_FIXED_ADDR {
		ptr = unsafe.Pointer(baseaddr)
		flagsMap |= _MAP_FIXED
	} else {
		ptr = unsafe.Pointer(nil) //TODO*(aghosn) check that this is correct for 0x0.
	}

	base, errno := runtime.RMmap(ptr, uintptr(secs.size), flagsProt, flagsMap, int32(sgxfd.Fd()), 0)

	if base == nil {
		log.Fatalf("Could not allocate memory for the enclave (baseaddress: %v -> %v)", baseaddr, errno)
	}

	secs.baseAddr = uint64(uintptr(base))
	secs.attributes = sigstruct.attributes
	secs.miscselect = sigstruct.miscselect
	secs.isvprodID = sigstruct.isvProdID
	secs.isvsvn = sigstruct.isvSvn
	secs.mrEnclave = sigstruct.enclaveHash
	secs.mrSigner = sha256.Sum256(sigstruct.modulus[:])
	secs.attributes.xfrm = 0x7

	//TODO(aghosn) check if that is correct to communicate with sgx module.
	parms := sgx_enclave_create{uintptr(unsafe.Pointer(&secs))}
	ptr = unsafe.Pointer(&parms)
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxfd.Fd()), uintptr(SGX_IOC_ENCLAVE_CREATE), uintptr(ptr))
	if int(err) != 0 {
		log.Fatalf("Error while creating enclave %v", err)
	}
	esize = secs.size
	return uintptr(secs.baseAddr)
}

func einit(base uintptr, sigstruct *sigstruct_t, token *einittoken_t) int {
	if sigstruct.vendor == 0x8086 {
		token = &einittoken_t{}
	}

	parm := sgx_enclave_init{addr: base,
		sigstruct:  uintptr(unsafe.Pointer(sigstruct)),
		einittoken: uintptr(unsafe.Pointer(token))}

	// Attempt to init the enclave with the launch token.
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxfd.Fd()),
		SGX_IOC_ENCLAVE_INIT,
		uintptr(unsafe.Pointer(&parm)))
	res := int(err)
	if res == 0 {
		return res
	}

	if res == ERR_SGX_INVALID_EINIT_TOKEN || res == ERR_SGX_INVALID_CPUSVN || res == ERR_SGX_INVALID_ISVSVN {
		//TODO(aghosn) create the new token etc.
		log.Fatalf("Need to create a new token!")
	}

	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxfd.Fd()),
		SGX_IOC_ENCLAVE_INIT,
		uintptr(unsafe.Pointer(&parm)))
	res = int(err)
	return res
}

func getLoadableSize(elf uintptr) int {
	return 0
}

func addPage(base, offset uintptr, prot uint64, p unsafe.Pointer) int {
	laddr := base + offset
	parm := sgx_enclave_add_page{addr: laddr, src: uintptr(p), mrmask: 0xffff}

	secinfo := isgx_secinfo{}
	if (prot & PAGE_TCS) == PAGE_TCS {
		secinfo.flags |= SGX_SECINFO_TCS
	} else {
		secinfo.flags |= SGX_SECINFO_REG
		if (prot & PAGE_READ) == PAGE_READ {
			secinfo.flags |= SGX_SECINFO_R
		}
		if (prot & PAGE_WRITE) == PAGE_WRITE {
			secinfo.flags |= SGX_SECINFO_W
		}
		if (prot & PAGE_EXEC) == PAGE_EXEC {
			secinfo.flags |= SGX_SECINFO_X
		}
	}

	if (prot & PAGE_NOEXTEND) == PAGE_NOEXTEND {
		parm.mrmask = 0
	}
	parm.secinfo = uintptr(unsafe.Pointer(&secinfo))
	ptr := uintptr(unsafe.Pointer(&parm))
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sgxfd.Fd()),
		SGX_IOC_ENCLAVE_ADD_PAGE,
		ptr)
	return int(err)
}

func getTlsInfo(p uintptr) (uint64, uint64, uint64) {
	ehdr := (*ElfEhdr)(unsafe.Pointer(p))
	base := p + uintptr(ehdr.phoff)

	vaddr, vsize, fsize := uint64(1), uint64(0), uint64(0)

	for i := uint16(0); i < ehdr.phnum; i++ {
		ptrAddr := base + uintptr(i)*unsafe.Sizeof(ElfPhdr{})
		phdr := (*ElfPhdr)(unsafe.Pointer(ptrAddr))

		if phdr.type_ == uint32(elf.PT_TLS) {
			vaddr, vsize, fsize = phdr.vaddr, phdr.memsz, phdr.filesz
		}
	}
	return vaddr, vsize, fsize
}

func getNextPower2(n uint64) uint64 {
	if ((n - 1) & n) == 0 {
		return n
	}
	power := uint64(2)
	for n != 0 {
		n >>= 1
		power <<= 1
	}
	return power
}
