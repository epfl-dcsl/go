package runtime

import (
	"unsafe"
)

// The goal is to provide a queue that is compatible with write barriers so that
// they can be used directly inside the schedule() function.
// We implement it for sudogs for the moment.
// For performance, it would be good to make it lockless to try lockless queues.
// For the moment, we will have a spinlock, and an interface to limit
// the number of trials before locking for non-critical operations.
// For the moment we have spinlocks inside the implementation of the queue.
// The goal would be to implement a semi-lock free structure (see p struct implementation)

type sguintptr uintptr

const (
	SGQMAXTRIALS = 10 // number of authorized spins. For debugging
)

type sgqueue struct {
	lock secspinlock
	head sguintptr
	tail sguintptr
	size int32
}

//go:nosplit
func (l sguintptr) ptr() *sudog {
	return (*sudog)(unsafe.Pointer(l))
}

//go:nosplit
func (l *sguintptr) set(sg *sudog) {
	*l = sguintptr(unsafe.Pointer(sg))
}

//go:nosplit
//go:nowritebarrier
func setSGNoWB(sg **sudog, new *sudog) {
	(*sguintptr)(unsafe.Pointer(sg)).set(new)
}

//sgqget pop sudog from the head of the lf sgqueue.
//This method locks the queue for the moment and does not fail.
func sgqget(q *sgqueue) *sudog {
	q.lock.Lock()
	if q.size == 0 {
		q.lock.Unlock()
		return nil
	}
	h := q.head.ptr()
	q.head = h.schednext
	q.size--
	if q.size == 0 {
		q.head = 0
		q.tail = 0
	}
	q.lock.Unlock()
	return h
}

//sgtryget does at most SGQMAXTRIALS attempts to lock the queue
//if it succeeds, it returns the element in the queue.
func sgqtryget(q *sgqueue) *sudog {
	if !q.lock.TryLockN(SGQMAXTRIALS) {
		return nil
	}
	if q.size == 0 {
		q.lock.Unlock()
		return nil
	}
	h := q.head.ptr()
	q.head = h.schednext
	q.size--
	if q.size == 0 {
		q.head = 0
		q.tail = 0
	}
	q.lock.Unlock()
	return h
}

//sgdrain removes all the *sudog in the queue at once.
func sgqdrain(q *sgqueue) (*sudog, int) {
	q.lock.Lock()
	if q.size == 0 {
		q.lock.Unlock()
		return nil, 0
	}
	h := q.head.ptr()
	s := q.size
	q.head = 0
	q.tail = 0
	q.size = 0
	q.lock.Unlock()
	return h, int(s)
}

func sgqtrydrain(q *sgqueue) (*sudog, int) {
	if !q.lock.TryLockN(SGQMAXTRIALS) {
		return nil, 0
	}

	if q.size == 0 {
		q.lock.Unlock()
		return nil, 0
	}
	h := q.head.ptr()
	s := q.size
	q.head = 0
	q.tail = 0
	q.size = 0
	q.lock.Unlock()
	return h, int(s)
}

//sgqput puts an element at the end of the queue.
//It sets the head as well if the queue is empty.
func sgqput(q *sgqueue, elem *sudog) {
	elem.schednext = 0
	q.lock.Lock()
	if q.tail != 0 {
		q.tail.ptr().schednext.set(elem)
	} else {
		q.head.set(elem)
	}
	q.tail.set(elem)
	q.size++
	q.lock.Unlock()
}

//sgqputbatch puts an entire batch at once inside the queue.
// WARNING: there is no check that n corresponds to the given list.
func sgqputbatch(q *sgqueue, sghead, sgtail *sudog, n int32) {
	sgtail.schednext = 0
	q.lock.Lock()
	if q.tail != 0 {
		q.tail.ptr().schednext.set(sghead)
	} else {
		q.tail.set(sghead)
	}
	q.tail.set(sgtail)
	q.size += n
	q.lock.Unlock()
}
