package gosec

/* This file implements a simulated environnement to load and execute enclave
 * binaries without sgx.
 */

import (
	"debug/elf"
	"log"
	"runtime"
	"syscall"
	"unsafe"
)

func loadProgram(path string) {
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
		mapSections(aggreg)
		aggreg = nil
		aggreg = append(aggreg, sec)
	}
	mapSections(aggreg)

	//TODO(aghosn) try to allocate the stack.
	prot := _PROT_READ | _PROT_WRITE
	addr := uintptr(0xe41ffd8000)
	size := int(0x8000)
	_, err = syscall.RMmap(addr, size, prot, _MAP_PRIVATE|_MAP_ANON, -1, 0)
	check(err)

	// Create the thread for enclave.
	fn := unsafe.Pointer(uintptr(file.Entry))

	//fn := unsafe.Pointer(uintptr(0x1879e0))
	runtime.AllocateOSThreadEncl(addr+uintptr(size), fn)
}

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
