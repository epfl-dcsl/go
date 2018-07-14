package gosec

/* This file implements a simulated environnement to load and execute enclave
 * binaries without sgx.
 */

import (
	"debug/elf"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sort"
	"syscall"
	"unsafe"
)

const simSTACK = uintptr(0xe41ffd8000)

func loadProgram(path string) {
	//SGXFull()
	//sgxLoadProgram(path)
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

	fmt.Println(path)
	out, err := exec.Command("bash", "-c", "go tool nm enclavebin | grep runtime.m0").Output() //exec.Command("bash", "-c", "go tool nm ", path, " | grep runtime.m0 ").Output()
	log.Println("The symbol is ", string(out))
	check(err)

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

	// write the value checked for TLS setup to differentiate between SIM and non SIM
	ptrFlag := (*uint64)(unsafe.Pointer(uintptr(MMMASK) + uintptr(SIM_OFF)))
	*ptrFlag = uint64(1)

	enclavePreallocate()
	// Create the thread for enclave.
	fn := unsafe.Pointer(uintptr(file.Entry))
	runtime.AllocateOSThreadEncl(wrap.stack+wrap.ssiz, fn)
}

func enclavePreallocate() {
	prot := _PROT_READ | _PROT_WRITE
	flags := _MAP_ANON | _MAP_FIXED | _MAP_PRIVATE

	for _, v := range runtime.EnclavePreallocated {
		_, err := syscall.RMmap(v.Addr, int(v.Size), prot, flags, -1, 0)
		check(err)
	}
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
