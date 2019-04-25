package runtime

import (
	"unsafe"
)

type DPTpe = _type

type CopyTpe func(unsafe.Pointer, *DPTpe) unsafe.Pointer

var (
	DeepCopier CopyTpe
)

func SetCopier(cp CopyTpe) {
	DeepCopier = cp
}

func storeCopy(dst unsafe.Pointer, val unsafe.Pointer, size uint16) {
	panic("bitch")
}
