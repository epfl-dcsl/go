package gosec

const (
	SGX_HASH_SIZE = 32
	SGX_MAC_SIZE  = 16

	METADATA_MAGIC   = uint64(0x86A80294635D0E4C)
	METADATA_VERSION = uint64(0x200000003)

	SE_KEY_SIZE      = 384 /* in bytes */
	SE_EXPONENT_SIZE = 4   /* RSA public key exponent size in bytes */
)

type sgx_measurement_t struct {
	m [SGX_HASH_SIZE]uint8
}
type sgx_attributes_t struct {
	flags uint64
	xfrm  uint64
}

type css_header_t struct { /* 128 bytes */
	header        [12]uint8 /* (0) must be (06000000E100000000000100H) */
	tpe           uint32    /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
	module_vendor uint32    /* (16) Intel=0x8086, ISV=0x0000 */
	date          uint32    /* (20) build date as yyyymmdd */
	header2       [16]uint8 /* (24) must be (01010000600000006000000001000000H) */
	hw_version    uint32    /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
	reserved      [84]uint8 /* (44) Must be 0 */
}

type css_key_t struct { /* 772 bytes */
	modulus   [SE_KEY_SIZE]uint8      /* (128) Module Public Key (keylength=3072 bits) */
	exponent  [SE_EXPONENT_SIZE]uint8 /* (512) RSA Exponent = 3 */
	signature [SE_KEY_SIZE]uint8      /* (516) Signature over Header and Body */
}

type css_body_t struct { /* 128 bytes */
	misc_select    miscselect_t      /* (900) The MISCSELECT that must be set */
	misc_mask      miscselect_t      /* (904) Mask of MISCSELECT to enforce */
	reserved       [20]uint8         /* (908) Reserved. Must be 0. */
	attributes     sgx_attributes_t  /* (928) Enclave Attributes that must be set */
	attribute_mask sgx_attributes_t  /* (944) Mask of Attributes to Enforce */
	enclave_hash   sgx_measurement_t /* (960) MRENCLAVE - (32 bytes) */
	reserved2      [32]uint8         /* (992) Must be 0 */
	isv_prod_id    uint16            /* (1024) ISV assigned Product ID */
	isv_svn        uint16            /* (1026) ISV assigned SVN */
}

type css_buffer_t struct { /* 780 bytes */
	reserved [12]uint8          /* (1028) Must be 0 */
	q1       [SE_KEY_SIZE]uint8 /* (1040) Q1 value for RSA Signature Verification */
	q2       [SE_KEY_SIZE]uint8 /* (1424) Q2 value for RSA Signature Verification */
}

type enclave_css_t struct { /* 1808 bytes */
	header css_header_t /* (0) */
	key    css_key_t    /* (128) */
	body   css_body_t   /* (900) */
	buffer css_buffer_t /* (1028) */
}

type metadata_t struct {
	magic_num            uint64 /* The magic number identifying the file as a signed enclave image */
	version              uint64 /* The metadata version */
	size                 uint32 /* The size of this structure */
	tcs_policy           uint32 /* TCS management policy */
	ssa_frame_size       uint32 /* The size of SSA frame in page */
	max_save_buffer_size uint32 /* Max buffer size is 2632 */
	desired_misc_select  uint32
	tcs_min_pool         uint32           /* TCS min pool*/
	enclave_size         uint64           /* enclave virtual size */
	attributes           sgx_attributes_t /*XFeatureMask to be set in SECS. */
	enclave_css          enclave_css_t    /* The enclave signature */
	//dirs                 [DIR_NUM]data_directory_t
	data [18592]uint8
}
