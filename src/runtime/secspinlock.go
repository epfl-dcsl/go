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
	f  uint32
	id uint32

	enclSuccess    uint32
	nonenclSuccess uint32

	enclhardLock    uint32
	nonenclhardLock uint32

	enclFail    uint32
	nonenclFail uint32
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
		if nbyields > 2000 {
			println("Fuu in secspsinlock")
			println("id:", sl.id)
			println("enclSuccess: ", sl.enclSuccess)
			println("nonenclSuccess: ", sl.nonenclSuccess)
			println("enclhardlock:", sl.enclhardLock)
			println("nonenclhardLock: ", sl.nonenclhardLock)
			println("enclFail:", sl.enclFail)
			println("nonenclFail:", sl.nonenclFail)
			throw("failure")
		}
	}

	if isEnclave {
		sl.enclhardLock++
	} else {
		sl.nonenclhardLock++
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
			if isEnclave {
				sl.enclSuccess++
			} else {
				sl.nonenclSuccess++
			}
			return true
		}
	}
	if isEnclave {
		sl.enclFail++
	} else {
		sl.nonenclFail++
	}
	return false
}

func (sl *secspinlock) Unlock() {
	if !atomic.Cas(&(sl.f), SSLOCKED, SSUNLOCKED) {
		panic("[secspinlock] problem unlocking.")
	}
}
