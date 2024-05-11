package traefik_oidc_auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func log(level string, format string, a ...interface{}) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	os.Stdout.WriteString(currentTime + " [" + level + "]" + " [traefik-oidc-auth] " + fmt.Sprintf(format, a...) + "\n")
}

func parseUrl(rawUrl string) (*url.URL, error) {
	if rawUrl == "" {
		return nil, errors.New("invalid empty url")
	}
	if !strings.Contains(rawUrl, "://") {
		rawUrl = "https://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	return u, nil
}

func getFullHost(req *http.Request) string {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")

	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = req.Host
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func (state *OidcState) base64Encode() (string, error) {
	stateBytes, err := json.Marshal(state)

	if err != nil {
		return "", err
	}

	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)
	return stateBase64, nil
}

func base64DecodeState(base64State string) (*OidcState, error) {
	stateBytes, err := base64.StdEncoding.DecodeString(base64State)

	if err != nil {
		return nil, err
	}

	var state OidcState
	err2 := json.Unmarshal(stateBytes, &state)
	if err2 != nil {
		return nil, err2
	}

	return &state, nil
}
