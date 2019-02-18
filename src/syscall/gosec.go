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
		syscid, csys := runtime.Cooprt.AcquireSysPool()
		_tpe := runtime.S3
		switch trap {
		case SYS_WRITE:
			destptr := runtime.UnsafeAllocator.Malloc(a3)
			memcpy(destptr, a2, a3)
			req := runtime.OcallReq{_tpe, trap, a1, destptr, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			runtime.UnsafeAllocator.Free(destptr, a3)
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
		case uintptr(318):
			destptr := runtime.UnsafeAllocator.Malloc(a2)
			req := runtime.OcallReq{_tpe, trap, destptr, a2, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			memcpy(destptr, a1, a2)
			runtime.UnsafeAllocator.Free(destptr, a2)
			return res.R1, res.R2, Errno(res.Err)
		case SYS_GETUID:
			req := runtime.OcallReq{_tpe, trap, a1, a2, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
		// For network part.
		case SYS_BIND:
			sockaddr := runtime.UnsafeAllocator.Malloc(a3)
			memcpy(sockaddr, a2, a3)
			req := runtime.OcallReq{_tpe, trap, a1, sockaddr, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			runtime.UnsafeAllocator.Free(sockaddr, a3)
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
		case SYS_LISTEN:
			req := runtime.OcallReq{_tpe, trap, a1, a2, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
		case SYS_ACCEPT:
			// copy the sockaddr
			sasize := unsafe.Sizeof(*(*RawSockaddrAny)(unsafe.Pointer(a2)))
			sockaddr := runtime.UnsafeAllocator.Malloc(sasize)
			memcpy(sockaddr, a2, sasize)
			//copy the socklen
			slsize := unsafe.Sizeof(*(*_Socklen)(unsafe.Pointer(a3)))
			socklen := runtime.UnsafeAllocator.Malloc(slsize)
			memcpy(socklen, a3, slsize)
			req := runtime.OcallReq{_tpe, trap, a1, sockaddr, socklen, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
			// copy back
			memcpy(a2, sockaddr, sasize)
			memcpy(a3, socklen, slsize)
			// free
			runtime.UnsafeAllocator.Free(sockaddr, sasize)
			runtime.UnsafeAllocator.Free(socklen, slsize)
		case SYS_READ:
			buf := runtime.UnsafeAllocator.Malloc(a3)
			req := runtime.OcallReq{_tpe, trap, a1, buf, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
			// copy back
			memcpy(a2, buf, a3)
			// free
			runtime.UnsafeAllocator.Free(buf, a3)
		default:
			panic("unsupported system call.")
			//goto UNSUPPORTED
		}

		runtime.Cooprt.ReleaseSysPool(syscid)
		return
	}
	return SSyscall(trap, a1, a2, a3)
}

func SRawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	if runtime.IsEnclave() {
		syscid, csys := runtime.Cooprt.AcquireSysPool()
		_tpe := runtime.RS3
		switch trap {
		case SYS_SOCKET:
			req := runtime.OcallReq{_tpe, trap, a1, a2, a3, 0, 0, 0, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
		default:
			panic("Not yet implemented")
		}
		runtime.Cooprt.ReleaseSysPool(syscid)
		return
	}
	panic("Not the enclave, should never have come here.")
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	if runtime.IsEnclave() {
		syscid, csys := runtime.Cooprt.AcquireSysPool()
		_tpe := runtime.S6
		switch trap {
		case SYS_SETSOCKOPT:
			// Copy the a4 (opt pointer)
			opt := runtime.UnsafeAllocator.Malloc(a5)
			memcpy(opt, a4, a5)
			req := runtime.OcallReq{_tpe, trap, a1, a2, a3, opt, a5, a6, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
			runtime.UnsafeAllocator.Free(opt, a5)
		case SYS_SENDTO:
			buf := runtime.UnsafeAllocator.Malloc(a3)
			memcpy(buf, a2, a3)
			sockaddr := runtime.UnsafeAllocator.Malloc(a6)
			memcpy(sockaddr, a5, a6)
			req := runtime.OcallReq{_tpe, trap, a1, buf, a3, a4, sockaddr, a6, syscid}
			runtime.Cooprt.Ocall <- req
			res := <-csys
			r1, r2, err = res.R1, res.R2, Errno(res.Err)
			runtime.UnsafeAllocator.Free(buf, a3)
			runtime.UnsafeAllocator.Free(sockaddr, a6)
		default:
			panic("Unallowed system call inside the enclave.")
		}
		runtime.Cooprt.ReleaseSysPool(syscid)
		return
	}
	return SSyscall6(trap, a1, a2, a3, a4, a5, a6)
}
