package teecert

import (
	"crypto/rsa"
	"runtime"
	"teecomm"
)

func check(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func TeeProtectKey(req chan *rsa.PrivateKey) {
	orig := <-req
	copy := &rsa.PrivateKey{}
	*copy = *orig
	req <- copy
}

func TeeDecryptService(comm chan teecomm.DecrRequestMsg) {
	runtime.GosecDBG("Starting a new TeeDecryptService")
	for {
		req := <-comm
		runtime.GosecDBG("received a req")
		err := rsa.DecryptPKCS1v15SessionKey(nil, req.Key, req.Msg, req.Plaintxt)
		check(err)
		runtime.GosecDBG("returning a reply")
		req.Done <- true
	}
}
