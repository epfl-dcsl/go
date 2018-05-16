package gosec

import (
	"debug/elf"
	"log"
	"unsafe"
)

/*
 * ELF header.
 */
type ElfEhdr struct {
	ident     [elf.EI_NIDENT]uint8
	type_     uint16
	machine   uint16
	version   uint32
	entry     uint64
	phoff     uint64
	shoff     uint64
	flags     uint32
	ehsize    uint16
	phentsize uint16
	phnum     uint16
	shentsize uint16
	shnum     uint16
	shstrndx  uint16
}

/*
 * Section header.
 */
type ElfShdr struct {
	name      uint32
	type_     uint32
	flags     uint64
	addr      uint64
	off       uint64
	size      uint64
	link      uint32
	info      uint32
	addralign uint64
	entsize   uint64
	shnum     int
}

/*
 * Program header.
 */
type ElfPhdr struct {
	type_  uint32
	flags  uint32
	off    uint64
	vaddr  uint64
	paddr  uint64
	filesz uint64
	memsz  uint64
	align  uint64
}

type ElfSym struct {
	name  uint32
	info  uint8
	other uint8
	shndx uint16
	value uint64
	size  uint64
}

func getSymbolAddress(p uintptr, symb string) uintptr {
	ehdr := (*ElfEhdr)(unsafe.Pointer(p))
	shaddr := p + uintptr(ehdr.shoff)
	shnum := ehdr.shnum

	num, entsize := uint64(0), uint64(0)
	strtab, dynsym := uintptr(0), uintptr(0)
	for i := uint16(0); i < shnum; i++ {
		addr := shaddr + uintptr(i)*unsafe.Sizeof(ElfShdr{})
		ptr := (*ElfShdr)(unsafe.Pointer(addr))

		if ptr.type_ == uint32(elf.SHT_STRTAB) {
			strtab = uintptr(ptr.off) + p
		}

		if ptr.type_ == uint32(elf.SHT_DYNSYM) {
			dynsym = uintptr(ptr.off) + p
			num = ptr.size / ptr.entsize
			entsize = ptr.entsize
		}

		if strtab != 0 && dynsym != 0 {
			break
		}
	}

	symbByte := []byte(symb)
	for s := uint64(0); s < num; s++ {
		symAddr := dynsym + uintptr(entsize)*uintptr(s)
		sym := (*ElfSym)(unsafe.Pointer(symAddr))
		if strcmp(uintptr(sym.name)+strtab, symbByte) {
			return uintptr(sym.value)
		}
	}
	log.Fatalf("cannot find symbol %v", symb)
	// Unreachable
	return 0
}
