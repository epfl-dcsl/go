package gosec

import (
	"debug/elf"
	"log"
	"unsafe"
)

func processPages(p, ubase uintptr, heap, stack uint64, tcsp, nssa int, pp func(uintptr, uintptr, uint64, unsafe.Pointer) int) {
	prot := uint64(PAGE_READ | PAGE_WRITE | PAGE_EXEC | PAGE_NOEXTEND)
	var page [4096]byte
	ptr := unsafe.Pointer(&page)
	pageoffset, srcpge := uintptr(0), uintptr(0)

	for i := uint64(0); i < heap; i++ {
		pp(ubase, pageoffset, prot, ptr)
		pageoffset += 0x1000
	}

	ehdr := (*ElfEhdr)(unsafe.Pointer(p))
	phdr := (*ElfPhdr)(unsafe.Pointer(uintptr(ehdr.phoff) + p))

	libbase := pageoffset
	prot = 0
	for i := uint16(0); i < ehdr.phnum; i++ {
		//TODO(aghosn) check that this is correct.
		addr := uintptr(unsafe.Pointer(phdr))
		ptr := (*ElfPhdr)(unsafe.Pointer(addr + unsafe.Sizeof(*phdr)*uintptr(i)))
		if ptr.type_ != uint32(elf.PT_LOAD) {
			continue
		}

		/* Segment might start from not a page-aligned address */
		pageoffset = uintptr(ptr.vaddr & 0xfffffffffffff000)
		npages := (ptr.vaddr - uint64(pageoffset) + ptr.filesz) / 0x1000

		segoffset := ptr.off + uint64(p)
		fileRead, memRead := uint64(0), uint64(0)

		if (ptr.flags & 0x4) != 0 {
			prot |= PAGE_READ
		}
		if (ptr.flags & 0x2) != 0 {
			prot |= PAGE_WRITE
		}
		if (ptr.flags & 0x1) != 0 {
			prot |= PAGE_EXEC
		}

		for k := uint64(0); k < npages; k++ {
			if k == 0 && pageoffset != uintptr(ptr.vaddr)-pageoffset {
				diff := uintptr(ptr.vaddr) - pageoffset
				memset(page[:], 0)
				dest, src := uintptr(unsafe.Pointer(&page))+diff, uintptr(segoffset)
				memcpy(dest, src, 0x1000-diff)

				srcpge = uintptr(unsafe.Pointer(&page))
				segoffset += 0x1000 - uint64(diff)
				fileRead += 0x1000 - uint64(diff)
			} else {
				srcpge = uintptr(segoffset)
				segoffset += 0x1000
				fileRead += 0x1000
			}
			//TODO(aghosn) looks weird to me here.
			pp(ubase, libbase+pageoffset, prot, unsafe.Pointer(srcpge))
			pageoffset += 4096
		}

		if ptr.filesz-fileRead > 0 {
			memset(page[:], 0)
			diff := uintptr(0)
			if npages == 0 && pageoffset != uintptr(ptr.vaddr) {
				diff = uintptr(ptr.vaddr) - pageoffset
			}

			srcpge = uintptr(unsafe.Pointer(&page))
			memcpy(srcpge+diff, uintptr(segoffset), uintptr(ptr.filesz-fileRead))
			pp(ubase, libbase+pageoffset, prot, unsafe.Pointer(srcpge))

			pageoffset += 4096
			npages++
			/* we should be done reading from file by now */
			memRead += 0x1000 - (ptr.filesz - fileRead)
			fileRead = ptr.filesz
		}

		memset(page[:], 0)
		rest := ptr.memsz - fileRead - memRead
		if rest > 0 {
			for n := uint64(0); n < rest/0x1000; n++ {
				pp(ubase, libbase+pageoffset, prot, unsafe.Pointer(&page))
				pageoffset += 4096
			}
		}

		if rest%0x1000 > 0 {
			pp(ubase, libbase+pageoffset, prot, unsafe.Pointer(&page))
			pageoffset += 4096
		}
	}

	enclaveSize := getEnclaveSize(heap, stack, tcsp, 1, nssa, int(pageoffset/0x1000), 1)
	pageoffset = libbase + pageoffset
	prot = PAGE_READ | PAGE_WRITE
	memset(page[:], 0)
	threads = make([]*enclave_thread_t, tcsp, tcsp)
	tcsMax = tcsp
	tlsVaddr, tlsFilesz, tlsMemsz := getTlsInfo(p)

	tlsStart := getSectionAddress(p, fileName, ".tdata")
	parmsOffset, start := uint64(0), uintptr(0)

	for i := uint64(0); i < tlsFilesz/8; i++ {
		addr := tlsStart + unsafe.Sizeof(i)*uintptr(i)
		ptr := (*uint64)(unsafe.Pointer(addr))
		if *ptr == 0xBAADF00DDEADBABE {
			start = addr
			parmsOffset = 8 * i
			break
		}
	}

	if start == 0 {
		log.Fatalf("Could not find the enclave parms in .tadata")
	}

	ossa := pageoffset
	for i := 0; i < tcsp; i++ {
		stackStart := uint64(pageoffset)
		for j := uint64(0); j < stack; j++ {
			pp(ubase, pageoffset, PAGE_READ|PAGE_WRITE, unsafe.Pointer(&page))
			pageoffset += 0x1000
		}

		// tls
		tls := pageoffset
		addr := uintptr(unsafe.Pointer(&page))
		tlsOffset := uint64(48)

		ptr := (*uint64)(unsafe.Pointer(addr))
		*ptr = uint64(tls) + tlsOffset + uint64(unsafe.Sizeof(enclave_parms_t{}))
		ptr = (*uint64)(unsafe.Pointer(addr + unsafe.Sizeof(uint64(0))))
		*ptr = uint64(pageoffset) + 0x1000
		ptr = (*uint64)(unsafe.Pointer(addr + unsafe.Sizeof(uint64(0))*2))
		*ptr = uint64(tls) + tlsOffset + parmsOffset

		addr = uintptr(unsafe.Pointer(&page)) + uintptr(tlsOffset) + uintptr(parmsOffset)
		enclParms := (*enclave_parms_t)(unsafe.Pointer(addr))
		enclParms.base, enclParms.heap = 0, 0 //TODO aghosn check that this is correct
		enclParms.stack = stackStart + stack*0x1000 - 8
		enclParms.ossa, enclParms.tcsn = uint64(ossa), uint64(tcsp)
		enclParms.tid, enclParms.heap_size = uint64(pageoffset), heap*0x1000
		enclParms.enclave_size, enclParms.tls_vaddr = enclaveSize, tlsVaddr
		enclParms.tls_filesz, enclParms.tls_memsz = tlsFilesz, tlsMemsz
		pp(ubase, pageoffset, prot, unsafe.Pointer(&page))
		pageoffset += 0x1000

		memset(page[:], 0)
		tcs := (*tcs_t)(unsafe.Pointer(&page))
		tcs.ossa, tcs.nssa = uint64(ossa), 2
		tcs.oentry = uint64(libbase + getSymbolAddress(p, "entry"))
		tcs.flags.setDbgoptin(0)
		tcs.ofsbasgx, tcs.ogsbasgx = uint64(tls), uint64(tls)
		tcs.fslimit, tcs.gslimit = 0x0fff, 0x0fff
		pp(ubase, pageoffset, PAGE_TCS, unsafe.Pointer(&page))
		threads[i].addr = pageoffset + ubase
		threads[i].busy = false
		pageoffset += 0x1000
	}
}

func memset(b []byte, val byte) {
	for i := range b {
		b[i] = val
	}
}

func memsetstruct(dest unsafe.Pointer, val byte, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		ptr := (*byte)(unsafe.Pointer(uintptr(dest) + i))
		*ptr = val
	}
}

func memcpy(dest, source, l uintptr) {
	for i := uintptr(0); i < l; i++ {
		d := (*byte)(unsafe.Pointer(dest + i))
		s := (*byte)(unsafe.Pointer(source + i))
		*d = *s
	}
}

//func memcopy(dest uintptr, src []byte) {
//	for i, b := range src {
//		addr := dest + uintptr(i)*unsafe.Sizeof(b)
//		ptr := (*byte)(unsafe.Pointer(addr))
//		*ptr = b
//	}
//}

func strcmp(p uintptr, bytes []byte) bool {
	for i := range bytes {
		addr := p + uintptr(i)
		ptr := (*byte)(unsafe.Pointer(addr))
		if *ptr != bytes[i] {
			return false
		}
	}
	return true
}

//func rmmap(addr, n, prot, flags, fd, off uintptr) (r1, r2 uintptr, errno syscall.Errno) {
//	return syscall.Syscall6(syscall.SYS_MMAP, addr, n, prot, flags, fd, off)
//}
