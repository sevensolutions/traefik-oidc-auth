package src

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

const (
	cookieChunkSize = 3072
	maxCookieChunks = 32
)

func setChunkedCookies(config *config.Config, rw http.ResponseWriter, cookieName string, cookieValue string) {
	cookieChunks := utils.ChunkString(cookieValue, cookieChunkSize)

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

	if chunkCount < 0 || chunkCount > maxCookieChunks {
		return 0, fmt.Errorf("cookie %s.Chunks contains an out of range chunk count of %d", cookieName, chunkCount)
	}

	return chunkCount, nil
}
func clearChunkedCookie(config *config.Config, rw http.ResponseWriter, req *http.Request, cookieName string) {
	baseCookie := createSessionCookie(config)
	baseCookie.Value = ""
	makeCookieExpireImmediately(baseCookie)

	for _, name := range presentChunkedCookieNames(req, cookieName) {
		c := *baseCookie
		c.Name = name
		http.SetCookie(rw, &c)
	}
}

func presentChunkedCookieNames(req *http.Request, cookieName string) []string {
	names := []string{cookieName}
	prefix := cookieName + "."

	for _, c := range req.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			names = append(names, c.Name)
		}
	}

	return names
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

func getCodeVerifierCookieName(config *config.Config) string {
	return makeCookieName(config, "CodeVerifier")
}

func getSessionCookieName(config *config.Config) string {
	return makeCookieName(config, "Session")
}

func makeCookieName(config *config.Config, name string) string {
	return fmt.Sprintf("%s.%s", config.CookieNamePrefix, name)
}

// clearLegacyCodeVerifierCookies expires PKCE cookies left by older builds.
// Temporary upgrade hygiene — safe to delete once those builds are gone.
//
// Browsers treat Domain=host and host-only (no Domain) as different cookies.
// We expire both. See makeCookieExpireImmediately for MaxAge=-1 behavior.
func clearLegacyCodeVerifierCookies(config *config.Config, rw http.ResponseWriter, req *http.Request, callbackURL *url.URL) {
	if callbackURL == nil {
		return
	}

	prefix := getCodeVerifierCookieName(config)
	path := callbackURL.Path
	// Hostname() strips any port. Domain with a port is invalid for Set-Cookie;
	// older code used url.Host and often ended up with host-only cookies instead.
	hostname := callbackURL.Hostname()

	names := map[string]struct{}{prefix: {}}
	for _, c := range req.Cookies() {
		if c.Name == prefix || strings.HasPrefix(c.Name, prefix+".") {
			names[c.Name] = struct{}{}
		}
	}

	for name := range names {
		domains := []string{""} // host-only
		if hostname != "" {
			domains = append(domains, hostname)
		}
		for _, domain := range domains {
			http.SetCookie(rw, makeCookieExpireImmediately(&http.Cookie{
				Name:     name,
				Value:    "",
				Secure:   true,
				HttpOnly: true,
				Path:     path,
				Domain:   domain,
				SameSite: http.SameSiteDefaultMode,
			}))
		}
	}
}
