package rules

import "net/http"

var httpFuncs = map[string]func(*matchersTree, ...string) error{
	"Header": headerFunc,
}

func headerFunc(tree *matchersTree, values ...string) error {
	headerName := values[0]
	headerValue := values[1]

	tree.matcher = func(req *http.Request) bool {

		h := req.Header.Get(headerName)

		return h == headerValue
	}

	return nil
}
