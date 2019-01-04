package runtime

import (
	"runtime/internal/atomic"
	"unsafe"
)

func gosecassert(b bool) {
	if !b {
		print("[enclave: ", isEnclave, "]")
		throw("Assertion failure")
	}
}

//TODO @aghosn remove afterwards.

const DEBUGMASK = 0x060000000000

//		DEBUGGING stuff that will need to be removed or replaced

func ForceGC() {
	for gosweepone() != ^uintptr(0) {
	}
}

var addr_debug uintptr = uintptr(DEBUGMASK)

func DebugTag(i int) {
	if isEnclave {
		ptr := (*uint64)(unsafe.Pointer(addr_debug))
		*ptr = uint64(i)
		addr_debug += unsafe.Sizeof(uint64(0))
	}
}

func DebugTagAt(offset, value int) {
	base := uintptr(DEBUGMASK + offset*8)
	ptr := (*uint64)(unsafe.Pointer(base))
	*ptr = uint64(value)
}

const (
	DBG_BEFORE_GOSECALL = iota
	DBG_IN_GOSECALL
	DBG_GOSEC_SEND
	DBG_GOSEC_SEND_DONE
	DBG_ACTUAL_SEND
	DBG_ACTUAL_SEND_DONE
	DBG_AFTER_GOSECALL
	DBG_RETURNED_GOSEC
	DBG_READ_CHAN
	DBG_ECALL_SRV
	DBG_ECALL_SRV2
	DBG_PRIV_SRV
	DBG_PRIV_SRV2
	DBG_ERROR_ECALL
	DBG_ENCL_GC
	DBG_NENCL_GC
	DBG_PRE_MOVE
	DBG_POST_MOVE
)

var DBG_NAMES = [20]string{
	"BEFORE GOSEC",
	"IN GOSEC FUNC",
	"IN GOSECSEND",
	"DONE GOSECSEND",
	"ACTUAL SEND",
	"ACTUAL SEND DONE",
	"AFTER GOSEC",
	"RETURNED GOSEC",
	"READ FROM CHAN",
	"ECALL SERVER",
	"ECALL SERVER2",
	"PRIVATE SERVER",
	"PRIVATE SERVER2",
	"ERROR ECALL",
	"ENCLAVE GC",
	"UNTRUST GC",
	"PRE MOVE",
	"POST MOVE",
}

func DebuggIncrease(i int) {
	atomic.Xaddint64(&Cooprt.Markers[i], 1)
}

func DebuggDumpMarkers() {
	for i, v := range Cooprt.Markers {
		println(DBG_NAMES[i], ":", i, ") ", v)
	}
}

func DebuggResetMarkers() {
	for i := range Cooprt.Markers {
		if i < DBG_ECALL_SRV && i > DBG_ECALL_SRV2 {
			Cooprt.Markers[i] = 0
		}
	}
}

func DebuggGCTS(i int) {
	ptr := (*uint64)(unsafe.Pointer(&Cooprt.Markers[i]))
	val := (uint64)(Cooprt.Markers[DBG_ACTUAL_SEND])
	atomic.Store64(ptr, val)
}
