package gosec

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

type sgx_enclave_create struct {
	src uint64
}

type sgx_enclave_init struct {
	addr       uintptr
	sigstruct  uintptr
	einittoken uintptr
}

type sgx_enclave_add_page struct {
	addr    uint64
	src     uint64
	secinfo uint64
	mrmask  uint16
}

type isgx_secinfo struct {
	flags    uint64
	reserved [7]uint64
}

type sgx_wrapper struct {
	base  uintptr
	siz   uintptr
	stack uintptr
	ssiz  uintptr
	alloc []byte
}
