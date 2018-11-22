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
	SGQMAXTRIALS = 5 // number of authorized spins. For debugging
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

func sgqgetnolock(q *sgqueue) *sudog {
	if q.size == 0 {
		return nil
	}
	h := q.head.ptr()
	q.head = h.schednext
	q.size--
	if q.size == 0 {
		q.head = 0
		q.tail = 0
	}
	return h
}

//sgqget pop sudog from the head of the lf sgqueue.
//This method locks the queue for the moment and does not fail.
func sgqget(q *sgqueue) *sudog {
	q.lock.Lock()
	if q.size == 0 {
		q.lock.Unlock()
		return nil
	}
	h := sgqget(q)
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
	h := sgqgetnolock(q)
	q.lock.Unlock()
	return h
}

func sgqdrainnolock(q *sgqueue) (*sudog, *sudog, int) {
	if q.size == 0 {
		return nil, nil, 0
	}
	h := q.head.ptr()
	t := q.tail.ptr()
	s := q.size
	q.head = 0
	q.tail = 0
	q.size = 0
	return h, t, int(s)
}

//sgdrain removes all the *sudog in the queue at once.
func sgqdrain(q *sgqueue) (*sudog, *sudog, int) {
	q.lock.Lock()
	if q.size == 0 {
		q.lock.Unlock()
		return nil, nil, 0
	}
	h, t, s := sgqdrainnolock(q)
	q.lock.Unlock()
	return h, t, s
}

func sgqtrydrain(q *sgqueue) (*sudog, *sudog, int) {
	if !q.lock.TryLockN(SGQMAXTRIALS) {
		return nil, nil, 0
	}
	if q.size == 0 {
		q.lock.Unlock()
		return nil, nil, 0
	}
	h, t, s := sgqdrainnolock(q)
	q.lock.Unlock()
	return h, t, s
}

func sgqputnolock(q *sgqueue, elem *sudog) {
	elem.schednext = 0
	if q.tail != 0 {
		q.tail.ptr().schednext.set(elem)
	} else {
		q.head.set(elem)
	}
	q.tail.set(elem)
	q.size++
}

func sgqtryput(q *sgqueue, elem *sudog) bool {
	if !q.lock.TryLockN(SGQMAXTRIALS) {
		return false
	}
	sgqputnolock(q, elem)
	q.lock.Unlock()
	return true
}

//sgqput puts an element at the end of the queue.
//It sets the head as well if the queue is empty.
func sgqput(q *sgqueue, elem *sudog) {
	q.lock.Lock()
	sgqputnolock(q, elem)
	q.lock.Unlock()
}

func sgqputbatchnolock(q *sgqueue, sghead, sgtail *sudog, n int32) {
	sgtail.schednext = 0
	if q.tail != 0 {
		q.tail.ptr().schednext.set(sghead)
	} else {
		if q.head != 0 {
			throw("sgqueue empty tail, non empty head!")
		}
		q.head.set(sghead)
	}
	q.tail.set(sgtail)
	q.size += n
}

//sgqputbatch puts an entire batch at once inside the queue.
// WARNING: there is no check that n corresponds to the given list.
func sgqputbatch(q *sgqueue, sghead, sgtail *sudog, n int32) {
	q.lock.Lock()
	sgqputbatchnolock(q, sghead, sgtail, n)
	q.lock.Unlock()
}

func sgqtryputbatch(q *sgqueue, sghead, sgtail *sudog, n int32) bool {
	if !q.lock.TryLockN(SGQMAXTRIALS) {
		return false
	}
	sgqputbatchnolock(q, sghead, sgtail, n)
	q.lock.Unlock()
	return true
}

//injectglistnolock allows to add the glist to the globalrunq.
//TODO Global runqueue NOT CHECKED OFTEN ENOUGH
//sched must be locked.
func injectglistnolock(glist *g) {
	if glist == nil {
		return
	}

	var n int
	for n = 0; glist != nil; n++ {
		gp := glist
		glist = gp.schedlink.ptr()
		gp.schedlink = 0
		ready(gp, 3+1, false)
	}
	_g_ := getg()
	if n != 0 && _g_.m.spinning {
		resetspinning()
	}
}
