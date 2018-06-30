package gosec

import (
	"crypto/sha256"
	"encoding/binary"
)

var data2hash []byte = nil
var meta *metadata_t

func sgxHashInit() {
	data2hash = make([]byte, 0)
	meta = &metadata_t{}
	meta.magic_num = METADATA_MAGIC
	meta.version = METADATA_VERSION
	meta.tcs_policy = 1
	meta.max_save_buffer_size = 2632
	meta.desired_misc_select = 0
	meta.tcs_min_pool = 1
}

func sgxSign(secs *secs_t) *metadata_t {
	meta := &metadata_t{}
	meta.magic_num = METADATA_MAGIC
	meta.version = METADATA_VERSION
	meta.tcs_policy = 1
	meta.ssa_frame_size = 1
	meta.max_save_buffer_size = 2632
	meta.desired_misc_select = 0
	meta.tcs_min_pool = 1
	meta.enclave_size = secs.size
	meta.attributes.flags = secs.attributes
	meta.attributes.xfrm = secs.xfrm

	// Populate the signature
	setHeader(&meta.enclave_css.header)
	setKey(&meta.enclave_css.key)
	setBody(&meta.enclave_css.body)
	meta.enclave_css.body.attributes.flags = secs.attributes
	meta.enclave_css.body.attributes.xfrm = secs.xfrm
	//TODO set the mask as well, need to handle it better.

	return nil
}

func setHeader(h *css_header_t) {
	header1 := [12]uint8{6, 0, 0, 0, 0xE1, 0, 0, 0, 0, 0, 1, 0}
	header2 := [16]uint8{1, 1, 0, 0, 0x60, 0, 0, 0, 0x60, 0, 0, 0, 1, 0, 0, 0}
	for i := range header1 {
		h.header[i] = header1[i]
	}

	for i := range header2 {
		h.header2[i] = header2[i]
	}

	h.tpe = 0
	h.module_vendor = 0
	//TODO modify this afterwards.
	h.date = 0x27061820
	h.hw_version = 0
	// Make sure they are zeroed.
	for i := range h.reserved {
		h.reserved[i] = 0
	}
}

func setKey(k *css_key_t) {
	//TODO nothing to do for now.
}

func setBody(b *css_body_t) {
	b.misc_mask.value = 0xff
	for i := range b.misc_mask.reversed2 {
		b.misc_mask.reversed2[i] = 0xff
	}
	b.isv_prod_id = 0
	b.isv_svn = 42
}

func sgxHashEcreate(secs *secs_t) {
	meta.enclave_size = secs.size
	meta.attributes.flags = secs.attributes
	meta.attributes.xfrm = secs.xfrm

	tmp := make([]byte, 64)
	offset := 0

	eheader := []byte("ECREATE\000")
	memcpy_s(tmp, eheader, offset, 8)
	offset += 8

	ssaFS := make([]byte, 4)
	binary.LittleEndian.PutUint32(ssaFS, secs.ssaFrameSize)
	memcpy_s(tmp, ssaFS, offset, 4)
	offset += 4

	secSize := make([]byte, 8)
	binary.LittleEndian.PutUint64(secSize, secs.size)
	memcpy_s(tmp, secSize, offset, 8)
	offset += 8
	for i := offset; i < len(tmp); i++ {
		tmp[i] = byte(0)
	}

	// Append it to the hash.
	data2hash = append(data2hash, tmp...)
}

func sgxHashEadd(secs *secs_t, secinfo *isgx_secinfo, daddr uintptr) {
	if daddr < uintptr(secs.baseAddr) {
		panic("gosec: invalid daddr out of range.")
	}
	tmp := make([]byte, 64)
	offset := 0

	eheader := []byte("EADD\000\000\000\000")
	memcpy_s(tmp, eheader, offset, 8)
	offset += 8

	off := uint64(daddr) - secs.baseAddr
	encloff := make([]byte, 8)
	binary.LittleEndian.PutUint64(encloff, off)
	memcpy_s(tmp, encloff, offset, 8)
	offset += 8

	flags := make([]byte, 8)
	binary.LittleEndian.PutUint64(flags, secinfo.flags)
	memcpy_s(tmp, flags, offset, 8)

	for i := offset; i < len(tmp); i++ {
		tmp[i] = byte(0)
	}

	// Add it to the signature.
	data2hash = append(data2hash, tmp...)
}

func sgxHashFinalize() {
	sig := sha256.Sum256(data2hash)
	for i := 0; i < SGX_HASH_SIZE; i++ {
		meta.enclave_css.body.enclave_hash.m[i] = sig[i]
	}
}

func memcpy_s(dst, src []byte, off, s int) {
	for i := 0; i < s; i++ {
		dst[off+i] = src[i]
	}
}
