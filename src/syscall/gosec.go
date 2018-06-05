package syscall

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	return SSyscall(trap, a1, a2, a3)
}
