package runtime

import (
	"runtime/internal/atomic"
)

const (
	mspins     = 10
	yspin      = 15
	ssunlocked = 0
	sslocked   = 1
)

type secspinlock struct {
	f  uint32
	id uint32

	enclock  uint32
	nenclock uint32

	enclfail  uint32
	nenclfail uint32
}

func (sl *secspinlock) Lock() {
	for !sl.TryLockN(SGQMAXTRIALS) {
		procyield(fastrandn(yspin) + 1)
	}

	if isEnclave {
		sl.enclock++
	} else {
		sl.nenclock++
	}
}

func (sl *secspinlock) TryLock() bool {
	res := atomic.Cas(&(sl.f), ssunlocked, sslocked)
	if res {
		gp := getg()
		gp.m.locks++
	}
	return res
}

// TryLockN attempts at most n times to acquire the spinlock.
func (sl *secspinlock) TryLockN(n int) bool {
	if n < 1 {
		return false
	}
	for i := 0; i < n; i++ {
		if sl.TryLock() {
			if isEnclave {
				sl.enclock++
			} else {
				sl.nenclock++
			}
			return true
		}
	}
	if isEnclave {
		sl.enclfail++
	} else {
		sl.nenclfail++
	}
	return false
}

func (sl *secspinlock) Unlock() {
	if v := atomic.Xchg(&(sl.f), ssunlocked); v != sslocked {
		panic("[secspinlock] problem unlocking.")
	}
	gp := getg()
	gp.m.locks--
}
