package runtime

import (
	"runtime/internal/atomic"
)

type secspinlock struct {
	f uint32
}

func (sl *secspinlock) Lock() {
	for !sl.TryLock() {
		//osyield()
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
