package runtime

import (
	"runtime/internal/atomic"
)

const (
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
	fails := 0
	gp := getg()
	gp.m.locks++
	for {
		for i := 0; i < SGQMAXTRIALS; i++ {
			for sl.f == ssunlocked {
				if atomic.Cas(&(sl.f), ssunlocked, sslocked) {
					if isEnclave {
						sl.enclock++
					} else {
						sl.nenclock++
					}
					return
				}
				fails++
			}

			procyield(fastrandn(yspin) + 1)
		}

		if fails > 100 {
			throw("fuck seriously that much contention?")
		}
	}
	//fails := 0
	//for !sl.TryLockN(SGQMAXTRIALS) {
	//	fails++
	//	if fails > 1000 {
	//		println(sl.id)
	//		throw("failing")
	//	}
	//	procyield(fastrandn(yspin) + 1)
	//}

	//if isEnclave {
	//	sl.enclock++
	//} else {
	//	sl.nenclock++
	//}
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
	gp := getg()
	gp.m.locks++
	for i := 0; i < n; i++ {
		for sl.f == ssunlocked {
			if ok := atomic.Cas(&(sl.f), ssunlocked, sslocked); ok {
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
	gp.m.locks--
	return false
}

func (sl *secspinlock) Unlock() {
	if v := atomic.Xchg(&(sl.f), ssunlocked); v != sslocked {
		panic("[secspinlock] problem unlocking.")
	}
	gp := getg()
	gp.m.locks--
}
