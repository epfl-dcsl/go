package gosecommon

import (
	"reflect"
	"unsafe"
)

func memcpy(dest, source, l uintptr) {
	for i := uintptr(0); i < l; i++ {
		d := (*byte)(unsafe.Pointer(dest + i))
		s := (*byte)(unsafe.Pointer(source + i))
		*d = *s
	}
}

// needsCopy checks the given type against the supported once and returns
// true if the type requires recursive exploring for copy.
func needsCopy(tpe reflect.Type) (bool, reflect.Kind) {
	switch tpe.Kind() {
	case reflect.Map:
		panic("Trying to deep copy a map...")
	case reflect.UnsafePointer:
		fallthrough
	case reflect.Ptr:
		fallthrough
	case reflect.Struct:
		// we force the inspection from deepcopy
		fallthrough
	case reflect.Array:
		fallthrough
	case reflect.Slice:
		return true, tpe.Kind()
	}
	return false, tpe.Kind()
}

func setPtrValue(ptr uintptr, val uintptr) {
	pptr := (*uintptr)(unsafe.Pointer(ptr))
	*pptr = val
}

func extractValue(ptr uintptr) uintptr {
	val := *(*uintptr)(unsafe.Pointer(ptr))
	return val
}

// deepCopy entry point for deepCopy.
// Takes a pointer type as element, returns pointer to the same type.
func deepCopy(src uintptr, tpe reflect.Type) uintptr {
	if tpe.Kind() != reflect.Ptr {
		panic("Call to deepCopy does not respect calling convention.")
	}
	// Initial shallow copy.
	destRoot := make([]uint8, tpe.Elem().Size())
	dest := uintptr(unsafe.Pointer(&destRoot[0]))
	memcpy(dest, src, tpe.Elem().Size())

	// Go into the type's deep copy
	deepCopy1(dest, src, tpe.Elem())
	return dest
}

// Add a store.
// deepCopy1 dest and src are pointers to type tpe.
func deepCopy1(dest, src uintptr, tpe reflect.Type) {
	b, k := needsCopy(tpe)
	if !b {
		// flat type, not interesting.
		return
	}
	switch k {
	case reflect.Ptr:
		// at that point dest and ptr should be ptrs to ptrs
		val := deepCopy(extractValue(src), tpe)
		setPtrValue(dest, val)
	case reflect.Struct:
		offset := uintptr(0)
		for i := 0; i < tpe.NumField(); i++ {
			f := tpe.Field(i)
			if b, _ := needsCopy(f.Type); b {
				deepCopy1(dest+offset, src+offset, f.Type)
			}
			offset += f.Type.Size()
		}
	case reflect.Array:
		if b, _ := needsCopy(tpe.Elem()); !b {
			return
		}
		offset := uintptr(0)
		for i := 0; i < tpe.Len(); i++ {
			deepCopy1(dest+offset, src+offset, tpe.Elem())
			offset += tpe.Elem().Size()
		}
	// TODO The case for the slice is weird, not sure how to handle it.
	case reflect.Slice:
		panic("Slices are not handled.")
	case reflect.UnsafePointer:
		panic("Unsafe pointers are not allowed!")
	default:
		panic("Unhandled type")
	}
}
