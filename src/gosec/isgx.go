package gosec

import (
	"fmt"
	"runtime"
)

//Not really used, just here for documentation.
const (
	SGX_ENCLU_EENTER  = 0x02
	SGX_ENCLU_ERESUME = 0x03
	SGX_ENCLU_EXIT    = 0x04
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
	tcss    []sgx_tcs_info
	mhstart uintptr // 0x1000
	mhsize  uintptr // 0x108000
	membuf  uintptr // To satisfy map(nil) requests
	alloc   []byte
	secs    *secs_t
	isSim   bool
	entry   uintptr // where to jump (asm_eenter or file.Entry)
}

type sgx_tcs_info struct {
	stack uintptr
	ssiz  uintptr
	tcs   uintptr // tcs size 0x1000.
	ssa   uintptr
	msgx  uintptr // size 0x1000, for the mglobal otherwise doesn't work
	tls   uintptr // size 0x1000
	entry uintptr // entry point for this tcs.
	used  bool
}

type spawnRequest struct {
	sid int     //tcs source id of requester
	gp  uintptr // the g that will be used for the new thread
	mp  uintptr // the m that will be used for the new thread
}

func (s *sgx_wrapper) DumpDebugInfo() {
	if runtime.Cooprt != nil {
		fmt.Printf("Cooprt at %p\n", runtime.Cooprt)
		fmt.Printf("Cooprt.Ecall %p, Cooprt.Ocall %p\n", runtime.Cooprt.EcallSrv, runtime.Cooprt.Ocall)
	}
	fmt.Printf("[DEBUG-INFO] wrapper at %p\n", s)
	fmt.Printf("{base: %x, siz: %x, mhstart: %x, mhsize: %x}\n", s.base, s.siz, s.mhstart, s.mhsize)
}

func (s *sgx_wrapper) DumpTcs() {
	tcs := s.defaultTcs()
	fmt.Printf("stack: %x, ssiz: %x, tcs: %x, msgx: %x, tls: %x\n", tcs.stack,
		tcs.ssiz, tcs.tcs, tcs.msgx, tcs.tls)
}

func (s *sgx_wrapper) defaultTcs() *sgx_tcs_info {
	if s.tcss == nil || len(s.tcss) == 0 {
		panic("Early call to get defaulttcs")
	}
	return &s.tcss[0]
}

func transposeOutWrapper(wrap *sgx_wrapper) *sgx_wrapper {
	trans := &sgx_wrapper{
		transposeOut(wrap.base), wrap.siz, nil,
		transposeOut(wrap.mhstart), wrap.mhsize,
		transposeOut(wrap.membuf), nil, wrap.secs, wrap.isSim,
		wrap.entry}

	trans.tcss = make([]sgx_tcs_info, len(wrap.tcss))
	for i := 0; i < len(wrap.tcss); i++ {
		trans.tcss[i] = transposeOutTCS(wrap.tcss[i])
	}
	return trans
}

func transposeOutTCS(orig sgx_tcs_info) sgx_tcs_info {
	return sgx_tcs_info{
		transposeOut(orig.stack), orig.ssiz, transposeOut(orig.tcs),
		transposeOut(orig.ssa), transposeOut(orig.msgx), transposeOut(orig.tls),
		transposeOut(orig.entry), orig.used}
}
