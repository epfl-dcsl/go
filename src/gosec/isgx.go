package gosec

import (
	"fmt"
	"runtime"
)

const (
	PAGE_READ     = 0x1
	PAGE_WRITE    = 0x2
	PAGE_EXEC     = 0x4
	PAGE_TCS      = 0x8
	PAGE_NOEXTEND = 0x10
)

const (
	SGX_SECINFO_R = 0x01
	SGX_SECINFO_W = 0x02
	SGX_SECINFO_X = 0x04
)

const (
	SGX_SECINFO_SECS = 0x000
	SGX_SECINFO_TCS  = 0x100
	SGX_SECINFO_REG  = 0x200
)

const (
	SGX_FS_LIMIT = 0xffffffff
	SGX_GS_LIMIT = 0xffffffff
)

const (
	TCS_N_SSA = 2
)

// Sizes for the different elements
const (
	STACK_SIZE  = 0x8000
	TCS_SIZE    = PSIZE
	SSA_SIZE    = PSIZE
	MSGX_SIZE   = PSIZE
	TLS_SIZE    = PSIZE
	MEMBUF_SIZE = runtime.MEMBUF_SIZE //(PSIZE * 300)
)

// Offsets are of the form FROM_TO_OFF = VALUE
const (
	STACK_TCS_OFF   = PSIZE
	TCS_SSA_OFF     = 0
	SSA_MSGX_OFF    = PSIZE
	MSGX_TLS_OFF    = 0
	TLS_MHSTART_OFF = PSIZE
)

var (
	RT_M0 = uintptr(0)
)

type sgx_enclave_create struct {
	src uint64
}

type sgx_enclave_init struct {
	addr       uint64
	sigstruct  uint64
	einittoken uint64
}

type sgx_enclave_add_page struct {
	addr    uint64
	src     uint64
	secinfo uint64
	mrmask  uint16 //bitmask for the 256 byte chunks that are to be measured
}

type isgx_secinfo struct {
	flags    uint64
	reserved [7]uint64
}

type sgx_wrapper struct {
	base    uintptr
	siz     uintptr
	stack   uintptr
	ssiz    uintptr
	tcs     uintptr // tcs size 0x1000.
	ssa     uintptr
	msgx    uintptr // size 0x1000
	tls     uintptr // size 0x1000
	mhstart uintptr // 0x1000
	mhsize  uintptr // 0x108000
	membuf  uintptr // To satisfy map(nil) requests
	alloc   []byte
}

func (s *sgx_wrapper) DumpDebugInfo() {
	fmt.Printf("[DEBUG-INFO] wrapper at %p\n", s)
	fmt.Printf("{base: %x, siz: %x, stack: %x, ssiz: %x, mhstart: %x, mhsize: %x}\n", s.base, s.siz, s.stack, s.ssiz, s.mhstart, s.mhsize)
}

func transposeOutWrapper(wrap *sgx_wrapper) *sgx_wrapper {
	trans := &sgx_wrapper{
		transposeOut(wrap.base), wrap.siz, transposeOut(wrap.stack),
		wrap.ssiz, transposeOut(wrap.tcs), transposeOut(wrap.ssa),
		transposeOut(wrap.msgx), transposeOut(wrap.tls),
		transposeOut(wrap.mhstart), wrap.mhsize,
		transposeOut(wrap.membuf), nil}
	return trans
}
