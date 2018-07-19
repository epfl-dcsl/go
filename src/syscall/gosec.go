package syscall

import (
	"runtime"
	"unsafe"
)

func memcpy(dest, source, l uintptr) {
	for i := uintptr(0); i < l; i++ {
		d := (*byte)(unsafe.Pointer(dest + i))
		s := (*byte)(unsafe.Pointer(source + i))
		*d = *s
	}
}

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	if runtime.IsEnclave() {
		switch trap {
		case SYS_WRITE:
			syscid, csys := runtime.Cooprt.AcquireSysPool()
			allocid, cal := runtime.Cooprt.AcquireAllocPool()

			//Copy the content of the buffer outside of the enclave.
			runtime.Cooprt.OAllocReq <- runtime.AllocAttr{int(a3), nil, allocid}
			buf := <-cal
			destptr := uintptr(unsafe.Pointer(&(buf.Buf[0])))
			memcpy(destptr, a2, a3)
			runtime.Cooprt.ReleaseAllocPool(allocid)

			// Make the call.
			runtime.Cooprt.Ocall <- runtime.OcallReq{false, trap, a1, destptr, a3, 0, 0, 0, syscid}
			res := <-csys
			runtime.Cooprt.ReleaseSysPool(syscid)
			return res.R1, res.R2, Errno(res.Err)
		default:
			goto UNSUPPORTED
		}

	}

UNSUPPORTED:
	return SSyscall(trap, a1, a2, a3)
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	//if runtime.IsEnclave() {
	//	switch trap {
	//	case SYS_READLINKAT:
	//		syscid, csys := runtime.Cooprt.AcquireSysPool()
	//		allocid, cal := runtime.Cooprt.AcquireAllocPool()

	//		// Compute the size of the string.
	//		size := uintptr(0)
	//		for {
	//			c := (*byte)(unsafe.Pointer(a2 + size))
	//			if *c == byte(0) {
	//				break
	//			}
	//			size++
	//		}
	//		size++ // account for null terminator

	//		//Copy the content of the string outside of the enclave.
	//		runtime.Cooprt.OAllocReq <- runtime.AllocAttr{int(size), nil, allocid}
	//		bufS := <-cal
	//		size = uintptr(0)
	//		for i := 0; i < len(bufS.Buf); i++ {
	//			val := (*byte)(unsafe.Pointer(a2 + size))
	//			bufS.Buf[i] = *val
	//			size++
	//		}

	//		//Allocate the buffer outside of the enclave.
	//		var na3 uintptr
	//		var bufU *runtime.AllocAttr
	//		if int(a4) > 0 {
	//			runtime.Cooprt.OAllocReq <- runtime.AllocAttr{int(a4), nil, allocid}
	//			bufU = <-cal
	//			na3 = uintptr(unsafe.Pointer(&bufU.Buf[0]))
	//		} else {
	//			na3 = uintptr(unsafe.Pointer(&_zero))
	//		}

	//		runtime.Cooprt.ReleaseAllocPool(allocid)

	//		na2 := uintptr(unsafe.Pointer(&bufS.Buf[0]))

	//		// Make the call.
	//		runtime.Cooprt.Ocall <- runtime.OcallReq{true, trap, a1, na2, na3, a4, a5, a6, syscid}
	//		res := <-csys
	//		runtime.Cooprt.ReleaseSysPool(syscid)

	//		//Copy back the buffer.
	//		if int(a4) > 0 {
	//			memcpy(a3, na3, a4)
	//		}
	//		return res.R1, res.R2, Errno(res.Err)

	//	default:
	//		goto UNSUPPORTED
	//	}
	//}
	//UNSUPPORTED:
	return SSyscall6(trap, a1, a2, a3, a4, a5, a6)
}
