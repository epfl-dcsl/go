package runtime

import (
	"runtime/internal/atomic"
)

const (
	yspin      = 4
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
		//procyield(fastrandn(yspin) + 1)
	}

	if isEnclave {
		sl.enclock++
	} else {
		sl.nenclock++
	}
}

func (sl *secspinlock) TryLock() bool {
	panic("Should not be called.")
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
		for sl.f == ssunlocked {
			if ok := atomic.Cas(&(sl.f), ssunlocked, sslocked); ok {
				gp := getg()
				gp.m.locks++
				if isEnclave {
					sl.enclock++
				} else {
					sl.nenclock++
				}
				return true
			}
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
