package src

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

func setChunkedCookies(config *Config, rw http.ResponseWriter, cookieName string, cookieValue string) {
	cookieChunks := utils.ChunkString(cookieValue, 3072)

	baseCookie := createSessionCookie(config)
	baseCookie.Name = cookieName

	// Set the cookie
	if len(cookieChunks) == 1 {
		c := baseCookie
		c.Value = cookieValue
		http.SetCookie(rw, c)
	} else {
		c := baseCookie
		c.Name = cookieName + ".Chunks"
		c.Value = fmt.Sprintf("%d", len(cookieChunks))
		http.SetCookie(rw, c)

		for index, chunk := range cookieChunks {
			c.Name = fmt.Sprintf("%s.%d", cookieName, index+1)
			c.Value = chunk
			http.SetCookie(rw, c)
		}
	}
}
func readChunkedCookie(req *http.Request, cookieName string) (string, error) {
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		return "", err
	}

	if chunkCount == 0 {
		cookie, err := req.Cookie(cookieName)
		if err != nil {
			return "", err
		}

		return cookie.Value, nil
	}

	value := ""

	for i := 0; i < chunkCount; i++ {
		cookie, err := req.Cookie(fmt.Sprintf("%s.%d", cookieName, i+1))
		if err != nil {
			return "", err
		}

		value += cookie.Value
	}

	return value, nil
}
func getChunkedCookieCount(req *http.Request, cookieName string) (int, error) {
	chunksCookie, err := req.Cookie(fmt.Sprintf("%s.Chunks", cookieName))
	if err != nil {
		return 0, nil
	}

	chunkCount, err := strconv.Atoi(chunksCookie.Value)
	if err != nil {
		return 0, err
	}

	return chunkCount, nil
}
func getChunkedCookieNames(req *http.Request, cookieName string) (map[string]struct{}, error) {
	cookieNames := make(map[string]struct{})
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		return nil, err
	}
	if chunkCount == 0 {
		cookieNames[cookieName] = struct{}{}
	} else {
		cookieNames[cookieName+".Chunks"] = struct{}{}
		for i := 0; i < chunkCount; i++ {
			cookieNames[fmt.Sprintf("%s.%d", cookieName, i+1)] = struct{}{}
		}
	}
	return cookieNames, nil
}
func clearChunkedCookie(config *Config, rw http.ResponseWriter, req *http.Request, cookieName string) error {
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		return err
	}

	baseCookie := createSessionCookie(config)
	baseCookie.Name = cookieName
	baseCookie.Value = ""
	makeCookieExpireImmediately(baseCookie)

	if chunkCount == 0 {
		http.SetCookie(rw, baseCookie)
	} else {
		c := baseCookie
		c.Name = cookieName + ".Chunks"
		http.SetCookie(rw, c)

		for i := 0; i < chunkCount; i++ {
			c.Name = fmt.Sprintf("%s.%d", cookieName, i+1)
			http.SetCookie(rw, c)
		}
	}

	return nil
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

func makeCookieExpireImmediately(cookie *http.Cookie) *http.Cookie {
	cookie.Expires = time.Now().Add(-24 * time.Hour)
	cookie.MaxAge = -1
	return cookie
}

func getCodeVerifierCookieName(config *Config) string {
	return makeCookieName(config, "CodeVerifier")
}
func getSessionCookieName(config *Config) string {
	return makeCookieName(config, "Session")
}
func makeCookieName(config *Config, name string) string {
	return fmt.Sprintf("%s.%s", config.CookieNamePrefix, name)
}
