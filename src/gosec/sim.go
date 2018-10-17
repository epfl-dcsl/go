package gosec

/* This file implements a simulated environnement to load and execute enclave
 * binaries without sgx.
 */

import (
	"debug/elf"
	"fmt"
	"log"
	"runtime"
	"sort"
	"syscall"
	"unsafe"
)

func loadProgram(path string) {
	fmt.Println("[DEBUG] loading the program in simulation.")
	file, err := elf.Open(path)
	check(err)
	_, wrap := sgxCreateSecs(file)
	defer func() { check(file.Close()) }()

	// Check that the sections are sorted now.
	sort.Sort(SortedElfSections(file.Sections))

	var aggreg []*elf.Section
	for _, sec := range file.Sections {
		if sec.Flags&elf.SHF_ALLOC != elf.SHF_ALLOC {
			continue
		}
		if len(aggreg) == 0 || aggreg[len(aggreg)-1].Flags == sec.Flags {
			aggreg = append(aggreg, sec)
			continue
		}
		mapSections(aggreg)
		aggreg = nil
		aggreg = append(aggreg, sec)
	}
	mapSections(aggreg)

	// Map the enclave preallocated heap.
	enclavePreallocate(wrap)

	// mmap the stack
	// try to allocate the stack.
	prot := _PROT_READ | _PROT_WRITE
	_, err = syscall.RMmap(wrap.stack, int(wrap.ssiz), prot, _MAP_PRIVATE|_MAP_ANON|_MAP_FIXED, -1, 0)
	check(err)

	// second stack
	prot = _PROT_READ | _PROT_WRITE
	ssiz := int(0x8000)
	_, err = syscall.RMmap(MMMASK, ssiz, prot, _MAP_PRIVATE|_MAP_ANON|_MAP_FIXED, -1, 0)
	check(err)

	// write the value checked for TLS-setup to differentiate between SIM and non SIM
	ptrFlag := (*uint64)(unsafe.Pointer(uintptr(SIM_FLAG)))
	*ptrFlag = uint64(1)

	// Map the MSGX+TLS area
	_, err = syscall.RMmap(wrap.msgx, int(MSGX_SIZE+MSGX_TLS_OFF+TLS_SIZE), prot,
		_MAP_ANON|_MAP_PRIVATE|_MAP_FIXED, -1, 0)
	check(err)

	//write the msgx value
	ptrMsgx := (*uint64)(unsafe.Pointer(uintptr(MSGX_ADDR)))
	*ptrMsgx = uint64(wrap.tls - uintptr(TLS_MSGX_OFF))

	// Create the thread for enclave.
	fn := unsafe.Pointer(uintptr(file.Entry))
	runtime.AllocateOSThreadEncl(wrap.stack+wrap.ssiz, fn, wrap.mhstart)
}

func enclavePreallocate(wrap *sgx_wrapper) {
	prot := _PROT_READ | _PROT_WRITE
	flags := _MAP_ANON | _MAP_FIXED | _MAP_PRIVATE

	// The span
	_, err := syscall.RMmap(wrap.mhstart, int(wrap.mhsize), prot,
		flags, -1, 0)
	check(err)

	// The memory buffer for mmap calls.
	_, err = syscall.RMmap(wrap.membuf, int(MEMBUF_SIZE), prot,
		flags, -1, 0)
	check(err)
}

// mapSections mmaps the elf sections.
// If wrap nil, simple mmap. Otherwise, mmap to another address space specified
// by wrap.mmask for SGX.
func mapSections(secs []*elf.Section) {
	if len(secs) == 0 {
		return
	}

	start := uintptr(secs[0].Addr)
	end := uintptr(secs[len(secs)-1].Addr + secs[len(secs)-1].Size)
	size := int(end - start)
	if start >= end {
		log.Fatalf("Error, sections are not ordered: %#x - %#x", start, end)
	}

	prot := _PROT_READ | _PROT_WRITE
	b, err := syscall.RMmap(start, size, prot, _MAP_PRIVATE|_MAP_ANON, -1, 0)
	check(err)

	for _, sec := range secs {
		if sec.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := sec.Data()
		check(err)
		offset := int(sec.Addr - uint64(start))
		for i := range data {
			b[offset+i] = data[i]
		}
	}
	prot = _PROT_READ
	if (secs[0].Flags & elf.SHF_WRITE) == elf.SHF_WRITE {
		prot |= _PROT_WRITE
	}

	if (secs[0].Flags & elf.SHF_EXECINSTR) == elf.SHF_EXECINSTR {
		prot |= _PROT_EXEC
	}

	err = syscall.Mprotect(b, prot)
	check(err)
}
