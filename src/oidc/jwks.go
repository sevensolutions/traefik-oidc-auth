package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

type JwksHandler struct {
	Url       string
	RsaKeys   []*RsaKey
	EcdsaKeys []*EcdsaKey
	CacheDate time.Time

	Lock sync.RWMutex
}

type JwksKey struct {
	Crv string `json:"crv,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	Use string `json:"use,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JwksKeys struct {
	Keys []JwksKey `json:"keys"`
}

type RsaKey struct {
	kid string
	key *rsa.PublicKey
}

type EcdsaKey struct {
	kid string
	key *ecdsa.PublicKey
}

func (h *JwksHandler) EnsureLoaded(logger *logging.Logger, httpClient *http.Client, forceReload bool) error {
	h.Lock.Lock()
	defer h.Lock.Unlock()

	now := time.Now()
	maxCacheTimeout := now.Add(-6 * time.Hour)
	minCacheTimeout := now.Add(-5 * time.Minute)

	reload := h.RsaKeys == nil && h.EcdsaKeys == nil

	if h.CacheDate.Compare(maxCacheTimeout) == -1 {
		reload = true
	}

	if forceReload && h.CacheDate.Compare(minCacheTimeout) == -1 {
		reload = true
	}

	if reload {
		logger.Log(logging.LevelInfo, "Reloading JWKS...")

		err := h.loadKeys(httpClient)
		if err != nil {
			logger.Log(logging.LevelError, "Error loading JWKS: %v", err)
		} else {
			logger.Log(logging.LevelInfo, "...JWKS reloaded :)")
		}

		return err
	}

	return nil
}

func (h *JwksHandler) loadKeys(httpClient *http.Client) error {
	resp, err := httpClient.Get(h.Url)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	loaded := JwksKeys{}
	err = json.NewDecoder(resp.Body).Decode(&loaded)

	if err != nil {
		return err
	}

	rsaKeys, ecdsaKeys, err := extractKeys(&loaded)
	if err != nil {
		return err
	}

	h.RsaKeys = rsaKeys
	h.EcdsaKeys = ecdsaKeys
	h.CacheDate = time.Now()

	return nil
}

func (h *JwksHandler) Keyfunc(token *jwt.Token) (any, error) {
	if strings.HasPrefix(token.Method.Alg(), "RS") {
		k, err := h.getRsaKey(token.Header["kid"].(string))

		if err != nil {
			return nil, err
		}

		return k, nil
	}

	if strings.HasPrefix(token.Method.Alg(), "EC") ||
		strings.HasPrefix(token.Method.Alg(), "ES") {
		k, err := h.getEcdsaKey(token.Header["kid"].(string))

		if err != nil {
			return nil, err
		}

		return k, nil
	}

	return nil, fmt.Errorf("unsupported algorithm %s", token.Method.Alg())
}

func (h *JwksHandler) getRsaKey(kid string) (*rsa.PublicKey, error) {
	k := h.findRsaKey(kid)

	if k != nil {
		return k.key, nil
	}

	return nil, errors.New("unknown kid " + kid)
}
func (h *JwksHandler) getEcdsaKey(kid string) (*ecdsa.PublicKey, error) {
	k := h.findEcdsaKey(kid)

	if k != nil {
		return k.key, nil
	}

	return nil, errors.New("unknown kid " + kid)
}

func (h *JwksHandler) findRsaKey(kid string) *RsaKey {
	for i := 0; i < len(h.RsaKeys); i++ {
		if kid == h.RsaKeys[i].kid {
			return h.RsaKeys[i]
		}
	}

	return nil
}
func (h *JwksHandler) findEcdsaKey(kid string) *EcdsaKey {
	for i := 0; i < len(h.EcdsaKeys); i++ {
		if kid == h.EcdsaKeys[i].kid {
			return h.EcdsaKeys[i]
		}
	}

	return nil
}

func extractKeys(keys *JwksKeys) ([]*RsaKey, []*EcdsaKey, error) {
	var rsaKeys []*RsaKey
	var ecdsaKeys []*EcdsaKey

	for i := 0; i < len(keys.Keys); i++ {
		k := keys.Keys[i]

		if k.Use == "sig" {
			if k.Kty == "RSA" {
				extracted, err := extractRsaKey(&k)

				if err == nil {
					rsaKeys = append(rsaKeys, extracted)
				}
			} else if k.Kty == "EC" {
				extracted, err := extractEcdsaKey(&k)

				if err == nil {
					ecdsaKeys = append(ecdsaKeys, extracted)
				}
			}
		}
	}

	if len(ecdsaKeys) == 0 && len(rsaKeys) == 0 {
		return nil, nil, errors.New("no public Keys found")
	}

	return rsaKeys, ecdsaKeys, nil
}
func extractRsaKey(key *JwksKey) (*RsaKey, error) {
	decodedN, err := utils.ParseBigInt(key.N)

	if err != nil {
		return nil, err
	}

	decodedE, err := utils.ParseInt(key.E)

	if err != nil {
		return nil, err
	}

	return &RsaKey{
		kid: key.Kid,
		key: &rsa.PublicKey{
			N: decodedN,
			E: decodedE},
	}, nil
}
func extractEcdsaKey(key *JwksKey) (*EcdsaKey, error) {
	decodedX, err := utils.ParseBigInt(key.X)

	if err != nil {
		return nil, err
	}

	decodedY, err := utils.ParseBigInt(key.Y)

	if err != nil {
		return nil, err
	}

	return &EcdsaKey{
		kid: key.Kid,
		key: &ecdsa.PublicKey{
			Curve: getEllipticCurve(key.Crv),
			X:     decodedX,
			Y:     decodedY},
	}, nil
}

func getEllipticCurve(crv string) elliptic.Curve {
	switch crv {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
