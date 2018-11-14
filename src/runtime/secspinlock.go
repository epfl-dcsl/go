package runtime

import (
	"runtime/internal/atomic"
)

const (
	mspins     = 10
	yspin      = 70
	SSUNLOCKED = 0
	SSLOCKED   = 1
	SSLOCKED2  = 2
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
	spins := 0
	//nbyields := 0
	for !sl.TryLock() {
		spins++
		if spins >= SGQMAXTRIALS {
			procyield(fastrandn(yspin) + 1)
			spins = 0
			//nbyields++
		}
		//if nbyields > 2000 {
		//	println("Fuu in secspsinlock")
		//	println("id:", sl.id)
		//	println("enclock: ", sl.enclock)
		//	println("nenclock: ", sl.nenclock)
		//	println("enclfail:", sl.enclfail)
		//	println("nenclfail: ", sl.nenclfail)
		//	throw("failure")
		//}
	}

	if isEnclave {
		sl.enclock++
	} else {
		sl.nenclock++
	}
}

func (sl *secspinlock) TryLock() bool {
	locking := uint32(SSLOCKED)
	if isEnclave {
		locking = SSLOCKED2
	}
	res := atomic.Cas(&(sl.f), SSUNLOCKED, locking)
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
	if v := atomic.Xchg(&(sl.f), SSUNLOCKED); v != SSLOCKED && v != SSLOCKED2 {
		panic("[secspinlock] problem unlocking.")
	}
	gp := getg()
	gp.m.locks--
}
