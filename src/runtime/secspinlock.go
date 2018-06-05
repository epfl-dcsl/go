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

func (sl *secspinlock) Unlock() {
	atomic.Cas(&(sl.f), 1, 0)
}
