package reflect

import (
	r "runtime"
	u "unsafe"
)

func ConvTypePtr(tpe *r.DPTpe) Type {
	rtpe := (*rtype)(u.Pointer(tpe))
	return PtrTo(rtpe)
}
