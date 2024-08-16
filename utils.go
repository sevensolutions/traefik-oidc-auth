package traefik_oidc_auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func log(minLevel string, level string, format string, a ...interface{}) {
	minLevel = strings.ToUpper(minLevel)
	level = strings.ToUpper(level)

	if (level == LogLevelError && (minLevel == LogLevelError || minLevel == LogLevelWarn || minLevel == LogLevelInfo || minLevel == LogLevelDebug)) ||
		(level == LogLevelWarn && (minLevel == LogLevelWarn || minLevel == LogLevelInfo || minLevel == LogLevelDebug)) ||
		(level == LogLevelInfo && (minLevel == LogLevelInfo || minLevel == LogLevelDebug)) ||
		(level == LogLevelDebug && minLevel == LogLevelDebug) {
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		os.Stdout.WriteString(currentTime + " [" + level + "]" + " [traefik-oidc-auth] " + fmt.Sprintf(format, a...) + "\n")
	}
}

func parseCookieSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteDefaultMode
	}
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

func ensureAbsoluteUrl(req *http.Request, url string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	} else {
		host := getFullHost(req)
		return host + url
	}
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

func fixGH10996(ymlArray []string) []string {
	firstEntry := ymlArray[0]

	realArray := strings.Split(firstEntry, "║")

	// Remove the first two entries. I don't know what they are.
	return realArray[2:]
}

func ParseBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)

	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(b), nil
}

func ParseInt(s string) (int, error) {
	v, err := ParseBigInt(s)

	if err != nil {
		return -1, err
	}

	return int(v.Int64()), nil
}

func encrypt(plaintext string, secret string) (string, error) {
	aes, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, secret string) (string, error) {
	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	ciphertext = string(cipherbytes)

	aes, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
