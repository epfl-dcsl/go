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
			if runtime.IsEnclave() {
				marker := (*uint64)(unsafe.Pointer(uintptr(0x050000000090)))
				*marker = uint64(0x111)
			}
			syscid, csys := runtime.Cooprt.AcquireSysPool()
			allocid, cal := runtime.Cooprt.AcquireAllocPool()

			//Copy the content of the buffer outside of the enclave.
			runtime.Cooprt.OAllocReq <- runtime.AllocAttr{int(a3), nil, allocid}
			buf := <-cal
			destptr := uintptr(unsafe.Pointer(&(buf.Buf[0])))
			memcpy(destptr, a2, a3)
			runtime.Cooprt.ReleaseAllocPool(allocid)

			// Make the call.
			req := runtime.OcallReq{false, trap, a1, destptr, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			runtime.Cooprt.ReleaseSysPool(syscid)
			return res.R1, res.R2, Errno(res.Err)
		default:
			if runtime.IsEnclave() {
				marker := (*uint64)(unsafe.Pointer(uintptr(0x050000000070)))
				*marker = uint64(0x666)
			}
			panic("unsupported system call.")
			//goto UNSUPPORTED
		}
	}

	return SSyscall(trap, a1, a2, a3)
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	if runtime.IsEnclave() {
		if runtime.IsEnclave() {
			marker := (*uint64)(unsafe.Pointer(uintptr(0x050000000070)))
			*marker = uint64(0x666)
		}
		panic("Unallowed system call inside the enclave.")
	}
	return SSyscall6(trap, a1, a2, a3, a4, a5, a6)
}
