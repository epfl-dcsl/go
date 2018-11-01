package runtime

import (
	"runtime/internal/atomic"
)

const (
	mspins = 10
	yspin  = 25
)

type secspinlock struct {
	f uint32
}

func (sl *secspinlock) Lock() {
	spins := 0
	for !sl.TryLock() {
		spins++
		if spins%mspins == 0 {
			procyield(yspin)
		}
		if spins > 1000 {
			println("Fuu in secspsinlock ", isEnclave)
			panic("shit")
		}
	}
}

func (sl *secspinlock) TryLock() bool {
	return atomic.Cas(&(sl.f), 0, 1)
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
	atomic.Cas(&(sl.f), 1, 0)
}
