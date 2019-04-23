package gosecommon

import (
	"reflect"
	r "runtime"
	"unsafe"
)

type Copy struct {
	start uintptr
	size  uintptr
}

type Store = map[uintptr]Copy

func memcpy(dest, source, l uintptr) {
	if dest == 0 || source == 0 {
		panic("nil argument to copy")
	}
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

func ignoreCopy(tpe reflect.Type) bool {
	return tpe == reflect.TypeOf(r.EcallReq{}) ||
		tpe == reflect.TypeOf(r.EcallServerReq{}) ||
		tpe == reflect.TypeOf(&r.EcallServerReq{})
}

func setPtrValue(ptr uintptr, val uintptr) {
	pptr := (*uintptr)(unsafe.Pointer(ptr))
	*pptr = val
}

func extractValue(ptr uintptr) uintptr {
	val := *(*uintptr)(unsafe.Pointer(ptr))
	return val
}

func DeepCopier(src unsafe.Pointer, tpe *r.DPTpe) unsafe.Pointer {
	store := make(Store)
	if store == nil {
		panic("Oh no")
	}
	gtpe := reflect.ConvTypePtr(tpe)
	return unsafe.Pointer(DeepCopy(uintptr(src), gtpe, store))
}

// deepCopy entry point for deepCopy.
// Takes a pointer type as element, returns pointer to the same type.
func DeepCopy(src uintptr, tpe reflect.Type, store Store) uintptr {
	if tpe.Kind() != reflect.Ptr {
		panic("Call to deepCopy does not respect calling convention.")
	}
	if v, ok := store[src]; ok {
		return v.start
	}
	// Initial shallow copy.
	destRoot := make([]uint8, tpe.Elem().Size())
	dest := uintptr(unsafe.Pointer(&destRoot[0]))
	memcpy(dest, src, tpe.Elem().Size())
	store[src] = Copy{dest, tpe.Elem().Size()}

	// Go into the type's deep copy
	deepCopy1(dest, src, tpe.Elem(), store)
	return dest
}

// TODO Add a store.
// deepCopy1 dest and src are pointers to type tpe.
func deepCopy1(dest, src uintptr, tpe reflect.Type, store Store) {
	b, k := needsCopy(tpe)
	if !b {
		// flat type, not interesting.
		return
	}
	switch k {
	case reflect.Ptr:
		// at that point dest and ptr should be ptrs to ptrs
		val := DeepCopy(extractValue(src), tpe, store)
		setPtrValue(dest, val)
	case reflect.Struct:
		offset := uintptr(0)
		for i := 0; i < tpe.NumField(); i++ {
			f := tpe.Field(i)
			if b, _ := needsCopy(f.Type); b {
				deepCopy1(dest+offset, src+offset, f.Type, store)
			}
			offset += f.Type.Size()
		}
	case reflect.Array:
		if b, _ := needsCopy(tpe.Elem()); !b {
			return
		}
		offset := uintptr(0)
		for i := 0; i < tpe.Len(); i++ {
			deepCopy1(dest+offset, src+offset, tpe.Elem(), store)
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
