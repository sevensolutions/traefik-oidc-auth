//go:build !appengine
// +build !appengine

package util

// NOTE: This is patched, because Yaegi doesn't support unsafe.

// BytesToString converts byte slice to string.
func BytesToString(b []byte) string {
	//return *(*string)(unsafe.Pointer(&b))
	return string(b)
}

// StringToBytes converts string to byte slice.
func StringToBytes(s string) []byte {
	// return *(*[]byte)(unsafe.Pointer(
	// 	&struct {
	// 		string
	// 		Cap int
	// 	}{s, len(s)},
	// ))
	return []byte(s)
}
