package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type AcceptType struct {
	Type   string
	Weight float64
}

// Expands the environment variable if it is enclosed in ${}. If the variable is not present, the original value is returned.
// Also supports reading the value from a file via ${file:/path/to/file}, eg. to consume a Docker/Kubernetes
// secret mounted as a file, since environment variables can be read by anyone with access to `docker inspect`.
func ExpandEnvironmentVariableString(value string) string {
	after, hasPrefix := strings.CutPrefix(value, "${")

	if hasPrefix {
		variableName, hasSuffix := strings.CutSuffix(after, "}")

		if hasSuffix {
			if filePath, isFile := strings.CutPrefix(variableName, "file:"); isFile {
				fileContent, err := os.ReadFile(filePath)

				if err == nil {
					return strings.TrimSpace(string(fileContent))
				}
			} else {
				variableValue, isDefined := os.LookupEnv(variableName)

				if isDefined {
					return variableValue
				}
			}
		}
	}

	return value
}

func ExpandEnvironmentVariableBoolean(value string, defaultValue bool) (bool, error) {
	after, hasPrefix := strings.CutPrefix(value, "${")

	if hasPrefix {
		variableName, hasSuffix := strings.CutSuffix(after, "}")

		if hasSuffix {
			variableValue, isDefined := os.LookupEnv(variableName)

			if isDefined {
				value = variableValue
			}
		}
	}

	if value == "true" || value == "1" {
		return true, nil
	} else if value == "false" || value == "0" {
		return false, nil
	} else if value != "" {
		return false, errors.New(fmt.Sprintf("Invalid boolean value \"%s\". Boolean values must be true/false or 1/0.", value))
	}

	return defaultValue, nil
}

func UrlIsAbsolute(u *url.URL) bool {
	return u.Scheme != "" && u.Host != ""
}

func ParseUrl(rawUrl string) (*url.URL, error) {
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

func getSchemeFromRequest(req *http.Request) string {
	scheme := req.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme
}

func FillHostSchemeFromRequest(req *http.Request, u *url.URL) *url.URL {
	scheme := getSchemeFromRequest(req)
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}
	u.Scheme = scheme
	u.Host = host
	return u
}

func GetFullHost(req *http.Request) string {
	scheme := getSchemeFromRequest(req)
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func EnsureAbsoluteUrl(req *http.Request, url string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	} else {
		host := GetFullHost(req)

		if !strings.HasPrefix(url, "/") {
			url = "/" + url
		}

		return host + url
	}
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

func Encrypt(plaintext string, secret string) (string, error) {
	aesCipher, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aesCipher)
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

func Decrypt(ciphertext string, secret string) (string, error) {
	if ciphertext == "" {
		return "", errors.New("ciphertext must not be an empty string")
	}

	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	ciphertext = string(cipherbytes)

	aesCipher, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aesCipher)
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

func ChunkString(input string, chunkSize int) []string {
	var chunks []string

	for i := 0; i < len(input); i += chunkSize {
		end := i + chunkSize
		if end > len(input) {
			end = len(input)
		}
		chunks = append(chunks, input[i:end])
	}

	return chunks
}

// ValidateRedirectUri checks redirectUri against validUris. Per the OIDC/OAuth2 spec, a
// redirect uri must match one of the registered ones exactly -- wildcardsEnabled is an
// explicit, operator-controlled opt-in (see the TOA_ENABLE_REDIRECT_URI_WILDCARDS env var)
// to relax that into the pattern matching implemented by matchUriTemplate, including the
// bare "*" entry that would otherwise accept anything.
func ValidateRedirectUri(redirectUri string, validUris []string, wildcardsEnabled bool) (string, error) {
	if redirectUri == "" {
		return "", nil
	}

	for _, validUri := range validUris {
		if redirectUri == validUri {
			return redirectUri, nil
		}

		if wildcardsEnabled && matchUriTemplate(redirectUri, validUri) {
			return redirectUri, nil
		}
	}

	return "", errors.New("invalid redirect uri")
}

// unsafePathPattern matches any attempt to walk up the directory tree, including the
// encoded and double-encoded variants of the separators and dots.
var unsafePathPattern = regexp.MustCompile(`(?i)(/|%2f|%5c|\\)(%2e|%252e|\.){2}(/|%2f|%5c|\\|;|%3b|%09|%0a|%0d|%00|$)`)

func matchUriTemplate(value string, template string) bool {
	if template == "*" {
		return true
	}

	vScheme, vAuthority, vPathAndBeyond, vHasAuthority := splitSchemeAuthorityPath(value)

	// Wildcards are only honored on a safe incoming uri: not a protocol-relative "//host"
	// reference (which splitSchemeAuthorityPath, keying on "://", wouldn't otherwise flag as
	// having an authority), and no directory-tree traversal in the path. Otherwise it has to
	// match one of the valid uris exactly. User-info spoofing (eg. "good.example.com@evil.com")
	// needs no check of its own -- matchAuthorityTemplate's anchored comparison rules it out.
	if strings.HasPrefix(value, "//") ||
		unsafePathPattern.MatchString(vPathAndBeyond) {
		return false
	}

	tScheme, tAuthority, tPathAndBeyond, tHasAuthority := splitSchemeAuthorityPath(template)

	// A template with a scheme/host (eg. "https://*.example.com/*") must not match a bare
	// path, and vice versa.
	if tHasAuthority != vHasAuthority {
		return false
	}

	if tHasAuthority {
		if tScheme != vScheme {
			return false
		}

		// A "*" glued directly onto the end of the host, with nothing after it at all (eg.
		// "https://example.com*" instead of "https://example.com/*"), is ambiguous -- almost
		// certainly a missing "/" before an intended path wildcard rather than a deliberate
		// host-label wildcard. Refuse it, unless it's actually a port wildcard (eg.
		// "https://example.com:*"), which is unambiguous since a "/" wouldn't make sense there.
		if tPathAndBeyond == "" && strings.HasSuffix(tAuthority, "*") {
			if beforeStar := strings.TrimSuffix(tAuthority, "*"); beforeStar != "" && !strings.HasSuffix(beforeStar, ":") {
				return false
			}
		}

		// The host is matched label by label: "*" stands in for exactly one subdomain label
		// and never crosses a "." on its own (eg. "*.example.com" doesn't match "a.b.example.com").
		if !matchAuthorityTemplate(vAuthority, tAuthority) {
			return false
		}
	}

	return matchPathTemplate(vPathAndBeyond, tPathAndBeyond)
}

// splitSchemeAuthorityPath splits off the scheme and authority (host[:port]) of a uri.
// pathAndBeyond is everything from there to the end of the string -- the path, and whatever
// follows it (query, fragment) -- left bundled together rather than parsed further, since
// that's matchPathTemplate's job.
func splitSchemeAuthorityPath(value string) (scheme string, authority string, pathAndBeyond string, hasAuthority bool) {
	schemeSeparatorIndex := strings.Index(value, "://")
	if schemeSeparatorIndex == -1 {
		return "", "", value, false
	}

	scheme = value[:schemeSeparatorIndex]
	rest := value[schemeSeparatorIndex+3:]

	if pathIndex := strings.IndexAny(rest, "/?#"); pathIndex != -1 {
		authority = rest[:pathIndex]
		pathAndBeyond = rest[pathIndex:]
	} else {
		authority = rest
		pathAndBeyond = ""
	}

	return scheme, authority, pathAndBeyond, true
}

func matchPathTemplate(value string, template string) bool {
	if value == template {
		return true
	}

	// A "*" is only a wildcard at the very end of the path and only if the template itself
	// carries no query or fragment. Everywhere else it is an ordinary character.
	if !strings.HasSuffix(template, "*") || strings.ContainsAny(template, "?#") {
		return false
	}

	// The query and the fragment of the incoming uri are not part of the comparison as
	// soon as a wildcard is in play.
	value = stripQueryAndFragment(value)

	// Everything below the prefix is matched, no matter how many segments it spans
	// (eg. "/app/*" matches "/app/index.html" as well as "/app/a/b").
	prefix := strings.TrimSuffix(template, "*")
	if strings.HasPrefix(value, prefix) {
		return true
	}

	// A trailing wildcard also matches the prefix itself, so "/app/*" matches "/app".
	return value == strings.TrimSuffix(prefix, "/")
}

func stripQueryAndFragment(value string) string {
	if index := strings.IndexAny(value, "?#"); index != -1 {
		return value[:index]
	}

	return value
}

func matchAuthorityTemplate(value string, template string) bool {
	if value == template {
		return true
	}

	// "*" stands in for exactly one host label: no "." (a label boundary), and no "@" (so a
	// value with a different host hidden behind user-info can never satisfy the pattern).
	escapedTemplate := regexp.QuoteMeta(template)
	escapedTemplate = strings.ReplaceAll(escapedTemplate, "\\*", "[a-zA-Z0-9-_]+")

	regex, err := regexp.Compile(fmt.Sprintf("^%s$", escapedTemplate))
	if err != nil {
		return false
	}

	return regex.MatchString(value)
}

func ParseAcceptType(raw string) AcceptType {
	// Parse MIME type and parameters
	mimeType, params, err := mime.ParseMediaType(raw)

	if err != nil {
		return AcceptType{}
	}

	weight := 1.0 // Default weight is 1.0

	// Take weight from the "q" parameter if it exists
	if weightString, ok := params["q"]; ok {
		weight, err = strconv.ParseFloat(weightString, 64)
		if err != nil {
			return AcceptType{}
		}
	}

	return AcceptType{
		Type:   mimeType,
		Weight: weight,
	}
}

func ParseAcceptHeader(raw string) []AcceptType {
	var acceptTypes []AcceptType

	for _, part := range strings.Split(raw, ",") {
		acceptType := ParseAcceptType(part)

		if acceptType.Type == "" {
			continue
		}

		acceptTypes = append(acceptTypes, acceptType)
	}

	// Sort by weight in descending order
	sort.Slice(acceptTypes, func(i, j int) bool {
		return acceptTypes[i].Weight > acceptTypes[j].Weight
	})

	return acceptTypes
}

func IsHtmlRequest(req *http.Request) bool {
	acceptTypes := ParseAcceptHeader(req.Header.Get("Accept"))

	if len(acceptTypes) == 0 {
		// Assume it's not an HTML request if no Accept header is present
		return false
	}

	// Assume HTML request have text/html or application/xhtml+xml with the highest weight
	return acceptTypes[0].Type == "text/html" || acceptTypes[0].Type == "application/xhtml+xml"
}
