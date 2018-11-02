package runtime

import (
	"runtime/internal/atomic"
)

const (
	mspins     = 10
	yspin      = 50
	SSLOCKED   = 1
	SSUNLOCKED = 0
)

type secspinlock struct {
	f uint32
}

func (sl *secspinlock) Lock() {
	spins := 0
	nbyields := 0
	for !sl.TryLockN(3) {
		spins++
		if spins >= mspins {
			procyield(fastrandn(yspin) + 1)
			spins = 0
			nbyields++
		}
		if nbyields > 1000 {
			println("Fuu in secspsinlock ", isEnclave)
			panic("shit")
		}
	}
}

func (sl *secspinlock) TryLock() bool {
	return atomic.Cas(&(sl.f), SSUNLOCKED, SSLOCKED)
}

// TryLockN attempts at most n times to acquire the spinlock.
func (sl *secspinlock) TryLockN(n int) bool {
	if n < 1 {
		return false
	}
	for i := 0; i < n; i++ {
		if sl.TryLock() {
			return true
		}
	}
	return false
}

func (sl *secspinlock) Unlock() {
	if !atomic.Cas(&(sl.f), SSLOCKED, SSUNLOCKED) {
		panic("[secspinlock] problem unlocking.")
	}
}
