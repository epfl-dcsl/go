package runtime

import (
	"runtime/internal/atomic"
	"unsafe"
)

// The goal is to provide a queue that is compatible with write barriers so that
// they can be used directly inside the schedule() function.
// We implement it for sudogs for the moment.
// For performance, it would be good to make it lockless to try lockless queues.
// For the moment, we will have a spinlock, and an interface to do a tryDequeue(n)
// which is the non critical operation.
// Use atomic operation though.

type lfuintptr uintptr

const (
	MAX_FAILS = 1000 // number of authorized spins. For debugging
)

type lfqueue struct {
	lock secspinlock
	head lfuintptr
	tail lfuintptr
	size int32
}

//go:nosplit
func (l lfuintptr) ptr() *sudog {
	return (*sudog)(unsafe.Pointer(l))
}

//go:nosplit
func (l *lfuintptr) set(sg *sudog) {
	*l = lfuintptr(unsafe.Pointer(sg))
}

//go:nosplit
//go:nowritebarrier
func setSGNoWB(sg **sudog, new *sudog) {
	(*lfuintptr)(unsafe.Pointer(sg)).set(new)
}

func Caslfuintptr(e *lfuintptr, o, n lfuintptr) bool {
	return atomic.Casuintptr((*uintptr)(unsafe.Pointer(e)), uintptr(o), uintptr(n))
}

//TODO @aghosn should test this one seriously.
// Pop from the head
//TODO Write a go test.
func lfdequeue(lf *lfqueue) *sudog {
	for i := 0; i < MAX_FAILS; i++ {
		head := lf.head //atomic.Loaduintptr(&lf.head)
		if head == 0 {
			return nil
		}
		nhead := head.ptr().schednext //atomic.Loaduintptr(&head.ptr().schednext)
		if Caslfuintptr(&lf.head, head, nhead) {
			if /*atomic.Loaduint(&lf.tail)*/ lf.tail == head {
				if !Caslfuintptr(&lf.tail, head, nhead) {
					panic("[lfdequeue] could not replace tail in empty list")
				}
			}
			return head.ptr()
		}
	}
	panic("[lfqueue] dequeue failure")
	return nil
}

// lfenqueue pushes an element at the end of the queue.
// It is responsible for making sure that the head is non empty.
// TODO @aghosn is that correct?
func lfenqueue(lf *lfqueue, elem *sudog) {
	elem.schednext = 0
	var tail lfuintptr = 0
	q := (lfuintptr)(unsafe.Pointer(elem))
	for i := 0; i < MAX_FAILS; i++ {
		p := lf.tail //atomic.Loaduintptr(&lf.tail)
		if p == 0 && Caslfuintptr(&lf.tail, 0, q) {
			if !Caslfuintptr(&lf.head, 0, q) {
				panic("[lfenqueue] unable to update head.")
			}
			return
		}
		if Caslfuintptr(&p.ptr().schednext, 0, q) {
			break
		}
	}
	if !Caslfuintptr(&lf.tail, tail, q) {
		panic("[lfenqueue] unable to update tail.")
	}
}
