package rules

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

var httpFuncs = map[string]func(*requestConditionTree, ...string) error{
	"Header":       headerFunc,
	"HeaderRegexp": headerRegexpFunc,
	"PathPrefix":   pathPrefixFunc,
	"Path":         pathFunc,
	"PathRegexp":   pathRegexpFunc,
	"Method":       methodFunc,
}

func headerFunc(tree *requestConditionTree, values ...string) error {
	if len(values) != 2 {
		return fmt.Errorf("Header-rule requires exactly two arguments.")
	}

	headerName := values[0]
	headerValue := values[1]

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		h := request.Header.Get(headerName)

		matched := h == headerValue

		logger.Log(logging.LevelDebug, "%s Eval rule Header(`%s`, `%s`). Actual value: %s", getMatchedText(matched), headerName, headerValue, h)

		return matched
	}

	return nil
}

func headerRegexpFunc(tree *requestConditionTree, values ...string) error {
	if len(values) != 2 {
		return fmt.Errorf("HeaderRegexp-rule requires exactly two arguments.")
	}

	headerName := values[0]
	headerValueRegex := values[1]

	headerRegex, err := regexp.Compile(headerValueRegex)
	if err != nil {
		return err
	}

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		h := request.Header.Get(headerName)

		matched := headerRegex.MatchString(h)

		logger.Log(logging.LevelDebug, "%s Eval rule HeaderRegexp(`%s`, `%s`). Actual value: %s", getMatchedText(matched), headerName, headerValueRegex, h)

		return matched
	}

	return nil
}

func pathFunc(tree *requestConditionTree, values ...string) error {
	if len(values) != 1 {
		return fmt.Errorf("Path-rule requires exactly one argument.")
	}

	expectedPath := values[0]

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		path := request.URL.Path

		matched := path == expectedPath

		logger.Log(logging.LevelDebug, "%s Eval rule Path(`%s`). Actual value: %s", getMatchedText(matched), expectedPath, path)

		return matched
	}

	return nil
}

func pathPrefixFunc(tree *requestConditionTree, values ...string) error {
	if len(values) != 1 {
		return fmt.Errorf("PathPrefix-rule requires exactly one argument.")
	}

	pathPrefix := values[0]

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		path := request.URL.Path

		matched := strings.HasPrefix(path, pathPrefix)

		logger.Log(logging.LevelDebug, "%s Eval rule PathPrefix(`%s`). Actual value: %s", getMatchedText(matched), pathPrefix, path)

		return matched
	}

	return nil
}

func pathRegexpFunc(tree *requestConditionTree, values ...string) error {
	if len(values) != 1 {
		return fmt.Errorf("PathRegexp-rule requires exactly one argument.")
	}

	pathValueRegex := values[0]

	pathRegex, err := regexp.Compile(pathValueRegex)
	if err != nil {
		return err
	}

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		path := request.URL.Path

		matched := pathRegex.MatchString(path)

		logger.Log(logging.LevelDebug, "%s Eval rule PathRegexp(`%s`). Actual value: %s", getMatchedText(matched), pathValueRegex, path)

		return matched
	}

	return nil
}

func methodFunc(tree *requestConditionTree, values ...string) error {
	if len(values) != 1 {
		return fmt.Errorf("Method-rule requires exactly one argument.")
	}

	expectedMethod := values[0]

	tree.matcher = func(logger *logging.Logger, request *http.Request) bool {
		method := request.Method

		matched := method == expectedMethod

		logger.Log(logging.LevelDebug, "%s Eval rule Method(`%s`). Actual value: %s", getMatchedText(matched), expectedMethod, method)

		return matched
	}

	return nil
}

func getMatchedText(matched bool) string {
	if matched {
		return "✅"
	} else {
		return "❌"
	}
}
