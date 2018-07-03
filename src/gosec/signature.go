package gosec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"io/ioutil"
	"os"
	"os/exec"
)

const (
	target = "/tmp/gobdump.dat"
)

var data2hash []byte = nil
var meta *metadata_t

func sgxHashInit() {
	data2hash = make([]byte, 0)
	meta = &metadata_t{}
	meta.Magic_num = METADATA_MAGIC
	meta.Version = METADATA_VERSION
	meta.Tcs_policy = 1
	meta.Max_save_buffer_size = 2632
	meta.Desired_misc_select = 0
	meta.Tcs_min_pool = 1
}

func sgxSign(secs *secs_t) *metadata_t {
	meta := &metadata_t{}
	meta.Magic_num = METADATA_MAGIC
	meta.Version = METADATA_VERSION
	meta.Tcs_policy = 1
	meta.Ssa_frame_size = 1
	meta.Max_save_buffer_size = 2632
	meta.Desired_misc_select = 0
	meta.Tcs_min_pool = 1
	meta.Enclave_size = secs.size
	meta.Attributes.Flags = secs.attributes
	meta.Attributes.Xfrm = secs.xfrm

	// Populate the signature
	setHeader(&meta.Enclave_css.Header)
	setKey(&meta.Enclave_css.Key)
	setBody(&meta.Enclave_css.Body)
	meta.Enclave_css.Body.Attributes.Flags = secs.attributes
	meta.Enclave_css.Body.Attributes.Xfrm = secs.xfrm
	//TODO set the mask as well, need to handle it better.

	return nil
}

func setHeader(h *css_header_t) {
	header1 := [12]uint8{6, 0, 0, 0, 0xE1, 0, 0, 0, 0, 0, 1, 0}
	header2 := [16]uint8{1, 1, 0, 0, 0x60, 0, 0, 0, 0x60, 0, 0, 0, 1, 0, 0, 0}
	for i := range header1 {
		h.Header[i] = header1[i]
	}

	for i := range header2 {
		h.Header2[i] = header2[i]
	}

	h.Tpe = 0
	h.Module_vendor = 0
	//TODO modify this afterwards.
	h.Date = 0x27061820
	h.Hw_version = 0
	// Make sure they are zeroed.
	for i := range h.Reserved {
		h.Reserved[i] = 0
	}
}

func setKey(k *css_key_t) {
	//TODO nothing to do for now.
}

func setBody(b *css_body_t) {
	b.Misc_mask.Value = 0xff
	for i := range b.Misc_mask.Reversed2 {
		b.Misc_mask.Reversed2[i] = 0xff
	}
	b.Isv_prod_id = 0
	b.Isv_svn = 42
}

func sgxHashEcreate(secs *secs_t) {
	meta.Enclave_size = secs.size
	meta.Attributes.Flags = secs.attributes
	meta.Attributes.Xfrm = secs.xfrm

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
		meta.Enclave_css.Body.Enclave_hash.M[i] = sig[i]
	}
}

func sgxTokenGetRequest(secs *secs_t) *LaunchTokenRequest {
	tokenreq := &LaunchTokenRequest{}
	tokenreq.MrSigner = []byte("trying") // key modulus.
	tokenreq.MrEnclave = meta.Enclave_css.Body.Enclave_hash.M[:]

	seattrib := make([]byte, 0)

	attrib := make([]byte, 8)
	binary.LittleEndian.PutUint64(attrib, secs.attributes)
	seattrib = append(seattrib, attrib...)

	xflags := make([]byte, 8)
	binary.LittleEndian.PutUint64(xflags, secs.xfrm)
	seattrib = append(seattrib, xflags...)

	tokenreq.SeAttributes = seattrib
	return tokenreq
}

func sgxTokenGetAesm(secs *secs_t) TokenGob {
	request := sgxTokenGetRequest(secs)

	f, err := os.Create("/tmp/gobdump_meta.dat")
	check(err)
	enc := gob.NewEncoder(f)
	err = enc.Encode(meta)
	check(err)

	f2, err := os.Create("/tmp/gobdump_req.dat")
	check(err)
	enc = gob.NewEncoder(f2)
	err = enc.Encode(request)
	check(err)

	cmd := exec.Command("serializer", "")
	err = cmd.Run()
	check(err)

	// Read the token.
	b, err := ioutil.ReadFile("/tmp/go_enclave.token")
	check(err)

	dec := gob.NewDecoder(bytes.NewReader(b))
	var token TokenGob
	err = dec.Decode(&token)
	check(err)
	return token
}

func memcpy_s(dst, src []byte, off, s int) {
	for i := 0; i < s; i++ {
		dst[off+i] = src[i]
	}
}
