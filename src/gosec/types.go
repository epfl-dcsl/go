package gosec

const (
	_PROT_NONE     = 0x0
	_PROT_READ     = 0x1
	_PROT_WRITE    = 0x2
	_PROT_EXEC     = 0x4
	_MAP_SHARED    = 0x01
	_MAP_PRIVATE   = 0x02
	_MAP_FIXED     = 0x10
	_MAP_ANON      = 0x20
	_MAP_NORESERVE = 0x4000
	SGX_MAGIC      = 0xA4

	ERR_SGX_INVALID_EINIT_TOKEN = 16
	ERR_SGX_INVALID_CPUSVN      = 32
	ERR_SGX_INVALID_ISVSVN      = 64
	//TODO(aghosn) for the moment I hardcode it, but should be more resilient.
	SGX_IOC_ENCLAVE_CREATE   = ((1 << 30) | (SGX_MAGIC << 8) | (0) | (8 << 16))
	SGX_IOC_ENCLAVE_ADD_PAGE = ((1 << 30) | (SGX_MAGIC << 8) | (0x01) | (26 << 16))
	SGX_IOC_ENCLAVE_INIT     = ((1 << 30) | (SGX_MAGIC << 8) | (0x02) | (24 << 16))

	SGX_ATTR_MODE64BIT = 0x04
)

type enclave_thread_t struct {
	busy bool
	addr uintptr
}

type EnclaveId uint64

type einittoken_t struct {
	valid              uint32
	reserved           [44]uint8
	attributes         attributes_t
	mrEnclave          [32]uint8
	reserved2          [32]uint8
	mrSigner           [32]uint8
	reserved3          [32]uint8
	cpuSvnLE           [16]uint8
	isvprodIDLE        uint16
	isvsvnLE           uint16
	reserved4          [24]uint8
	maskedmiscSelectLE miscselect_t
	maskedAttributesLE attributes_t
	keyid              [32]uint8
	mac                [16]uint8
}

type sigstruct_t struct {
	header        [16]uint8
	vendor        uint32
	date          uint32
	header2       [16]uint8
	swdefined     uint32
	reserved1     [84]uint8
	modulus       [384]uint8
	exponent      uint32
	signature     [384]uint8
	miscselect    miscselect_t
	miscmask      miscselect_t
	reserved2     [20]uint8
	attributes    attributes_t
	attributeMask attributes_t
	enclaveHash   [32]uint8
	reserved3     [32]uint8
	isvProdID     uint16
	isvSvn        uint16
	reserved4     [12]uint8
	q1            [384]uint8
	q2            [384]uint8
}

type __jmp_buf struct {
	rbx uint32
	rsp uint32
	rbp uint32
	r12 uint32
	r13 uint32
	r14 uint32
	r15 uint32
	rip uint32
}

type jmp_buf struct {
	__jb __jmp_buf
	__fl uint32
	__ss [4]uint32
}

/* Enclave parameters, maintained within enclave */
type enclave_parms_t struct {
	base         uint64
	heap         uint64
	stack        uint64
	ossa         uint64
	tcsn         uint64
	heap_size    uint64
	exit_addr    uint64
	ursp         uint64
	urbp         uint64
	stack_size   uint64
	enclave_size uint64
	tid          uint64
	tls_vaddr    uint64
	tls_filesz   uint64
	tls_memsz    uint64
	thread_state uint64
	eh_tcs_addr  uint64
	eh_exit_addr uint64
	eh_ursp      uint64
	eh_urbp      uint64
	eh_handling  uint64
	regs         jmp_buf
}

// XXX:Separate reserved -> reserved1, reserved2 to remove warning
type tcs_flags_t struct {
	value     uint32
	reserved2 uint32
}

func (t *tcs_flags_t) getDbgoptin() uint32 {
	return t.value & 0x1
}

func (t *tcs_flags_t) setDbgoptin(v uint32) {
	t.value >>= 1
	t.value <<= 1
	t.value |= (v & 0x1)
}

func (t *tcs_flags_t) getReserved1() uint32 {
	return (t.value >> 1)
}

func (t *tcs_flags_t) setReserved1(v uint32) {
	t.value = (t.value & 0x1) | (v << 1)
}

type tcs_t struct {
	reserved1 uint64
	flags     tcs_flags_t //!< Thread's Execution Flags
	ossa      uint64
	cssa      uint32
	nssa      uint32
	oentry    uint64
	reserved2 uint64
	ofsbasgx  uint64 //!< Added to Base Address of Enclave to get FS Address
	ogsbasgx  uint64 //!< Added to Base Address of Enclave to get GS Address
	fslimit   uint32
	gslimit   uint32
	reserved3 [503]uint64
}

type secs_t struct {
	size                   uint64 //!< Size of enclave in bytes; must be power of 2
	baseAddr               uint64 //!< Enclave base linear address must be naturally aligned to size
	ssaFrameSize           uint32 //!< Size of 1 SSA frame in pages(incl. XSAVE)
	miscselect             miscselect_t
	reserved1              [24]uint8
	attributes             uint64 //!< Attributes of Enclave: (pg 2-4)
	xfrm                   uint64
	mrEnclave              [32]uint8 //!< Measurement Reg of encl. build process
	reserved2              [32]uint8
	mrSigner               [32]uint8 //!< Measurement Reg extended with pub key that verified the enclave
	reserved3              [96]uint8
	isvprodID              uint16 //!< Product ID of enclave
	isvsvn                 uint16 //!< Security Version Number (SVN) of enclave
	mrEnclaveUpdateCounter uint64 //!< Hack: place update counter here
	eid_reserved           secs_eid_reserved_t
}

type miscselect_t struct {
	Value     uint8
	Reversed2 [3]uint8
}

type attributes_t struct {
	value     uint8
	reserved4 [7]uint8
	xfrm      uint64
}

// TODO(aghosn) fix this: reserved and eid/pad should overlap according to the sgx reference
type secs_eid_reserved_t struct {
	eid_pad  secs_eid_pad_t
	reserved [3836]uint8 //!< Reserve 8 bytes for update counter.
}

// (ref 2.7, table 2-2)
type secs_eid_pad_t struct {
	eid     uint64     //!< Enclave Identifier
	padding [352]uint8 //!< Padding pattern from Signature
}

func (m *miscselect_t) getExitinfo() uint8 {
	return m.Value & 0x1
}

func (m *miscselect_t) seExitinfo(v uint8) {
	setBit(&m.Value, v, 0)
}

func (m *miscselect_t) getReversed1() uint8 {
	return m.Value & 0xFE
}

func (m *miscselect_t) setReserved1(v uint8) {
	m.Value &= (v | 0x1)
}

func (a *attributes_t) getReserved1() uint8 {
	return a.value & 0x1
}

func (a *attributes_t) setReserved1(v uint8) {
	setBit(&a.value, v, 0)
}

func (a *attributes_t) getDebug() uint8 {
	return a.value & 0x2
}

func (a *attributes_t) setDebug(v uint8) {
	setBit(&a.value, v, 1)
}

func (a *attributes_t) getMode64Bit() uint8 {
	return a.value & 0x4
}

func (a *attributes_t) setMode64Bit(v uint8) {
	setBit(&a.value, v, 2)
}

func (a *attributes_t) getReserved2() uint8 {
	return a.value & 0x8
}

func (a *attributes_t) setReserved2(v uint8) {
	setBit(&a.value, v, 3)
}

func (a *attributes_t) getProvisionKey() uint8 {
	return a.value & 0x16
}

func (a *attributes_t) setProvisionKey(v uint8) {
	setBit(&a.value, v, 4)
}

func (a *attributes_t) getEinittokenkey() uint8 {
	return a.value & 0x24
}

func (a *attributes_t) setEinittokenkey(v uint8) {
	setBit(&a.value, v, 5)
}

func (a *attributes_t) getReserved3() uint8 {
	return a.value & (3 << 6)
}

func (a *attributes_t) setReversed3(v uint8) {
	v &= 0xC0
	a.value &= 0xC0
	a.value |= v
}

func setBit(value *uint8, bit, pos uint8) {
	*value &= ^(1 << pos)
	*value |= ((bit & 0x1) << pos)
}
