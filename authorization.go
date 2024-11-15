package traefik_oidc_auth

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/spyzhov/ajson"
)

func (toa *TraefikOidcAuth) isAuthorized(claims map[string]interface{}) bool {
	authorization := toa.Config.Authorization

	if authorization.AssertClaims != nil && len(authorization.AssertClaims) > 0 {
		parsed, err := json.Marshal(claims)
		if err != nil {
			log(toa.Config.LogLevel, LogLevelWarn, "Error whilst marshalling claims object: %s", err.Error())
			return false
		}

	assertions:
		for _, assertion := range authorization.AssertClaims {
			value, err := ajson.JSONPath(parsed, fmt.Sprintf("$.%s", assertion.Name))
			if err != nil {
				log(toa.Config.LogLevel, LogLevelWarn, "Error whilst parsing path for claim %s in token claims: %s", assertion.Name, err.Error())
				return false
			} else if len(value) == 0 {
				log(toa.Config.LogLevel, LogLevelWarn, "Unauthorized. Unable to find claim %s in token claims.", assertion.Name)
				toa.logAvailableClaims(claims)
				return false
			}

			if len(assertion.AllOf) == 0 && len(assertion.AnyOf) == 0 {
				log(toa.Config.LogLevel, LogLevelDebug, "Authorized claim %s. No assertions were defined and claim exists", assertion.Name)
				continue assertions
			}

			// check all matched nodes whether for one of the nodes all assertions hold
			// should the assertions hold for no node we return `false` to indicate
			// an unauthorized state

			allMatches := make([]bool, len(assertion.AllOf))
			anyMatch := false

		matches:
			for _, val := range value {
				unpacked, err := val.Unpack()
				if err != nil {
					log(toa.Config.LogLevel, LogLevelError, "Error whilst unpacking json node: %s", err.Error())
					continue matches
				}

				switch val := unpacked.(type) {
				// the value is any array
				case []interface{}:
					mapped := make([]string, len(val))
					for i, rawVal := range val {
						mapped[i] = fmt.Sprintf("%v", rawVal)
					}

					// first check whether allOf assertion is fulfilled -> return false if not
					if len(assertion.AllOf) > 0 {
						for _, assert := range assertion.AllOf {
							if !slices.Contains(mapped, assert) {
								break matches
							}
						}
					}
					// should allOf assertion be fulfilled check whether anyOf assertion is fulfilled -> return true when fulfilled
					if len(assertion.AnyOf) > 0 {
						for _, assert := range assertion.AnyOf {
							if slices.Contains(mapped, assert) {
								log(toa.Config.LogLevel, LogLevelDebug, "Authorized claim %s: Found value %s which is any of [%s]", assertion.Name, assert, strings.Join(assertion.AnyOf, ", "))
								continue assertions
							}
						}
						continue matches
					}
					log(toa.Config.LogLevel, LogLevelDebug, "Authorized claim %s: Found all values of [%s]", assertion.Name, strings.Join(assertion.AllOf, ", "))
					continue assertions
				// the value is any other json type
				default:
					strVal := fmt.Sprintf("%v", val)
					if len(assertion.AnyOf) > 0 {
						if slices.Contains(assertion.AnyOf, strVal) {
							anyMatch = true
						}
					}
					if len(assertion.AllOf) > 0 {
						for i, assert := range assertion.AllOf {
							if assert == strVal {
								allMatches[i] = true
								break
							}
						}
					}
					continue matches
				}
			}

			if len(assertion.AnyOf) > 0 && anyMatch && len(assertion.AllOf) > 0 && !slices.Contains(allMatches, false) {
				log(toa.Config.LogLevel, LogLevelDebug, "Authorized claim %s: Found any value of [%s] and all values of [%s]", assertion.Name, strings.Join(assertion.AnyOf, ", "), strings.Join(assertion.AllOf, ", "))
				continue assertions
			} else if len(assertion.AnyOf) > 0 && anyMatch && len(assertion.AllOf) == 0 {
				log(toa.Config.LogLevel, LogLevelDebug, "Authorized claim %s: Found any value of [%s]", assertion.Name, strings.Join(assertion.AnyOf, ", "))
				continue assertions
			} else if len(assertion.AllOf) > 0 && !slices.Contains(allMatches, false) && len(assertion.AnyOf) == 0 {
				log(toa.Config.LogLevel, LogLevelDebug, "Authorized claim %s: Found all values of [%s]", assertion.Name, strings.Join(assertion.AllOf, ", "))
				continue assertions
			}

			if len(assertion.AllOf) > 0 && len(assertion.AnyOf) > 0 {
				log(toa.Config.LogLevel, LogLevelWarn, "Unauthorized. Expected claim %s to contain any value of [%s] and all values of [%s]", assertion.Name, strings.Join(assertion.AnyOf, ", "), strings.Join(assertion.AllOf, ", "))
			} else if len(assertion.AllOf) > 0 {
				log(toa.Config.LogLevel, LogLevelWarn, "Unauthorized. Expected claim %s to contain all values of [%s]", assertion.Name, strings.Join(assertion.AllOf, ", "))
			} else if len(assertion.AnyOf) > 0 {
				log(toa.Config.LogLevel, LogLevelWarn, "Unauthorized. Expected claim %s to contain any value of [%s]", assertion.Name, strings.Join(assertion.AnyOf, ", "))
			}

			toa.logAvailableClaims(claims)

			return false
		}
	}

	return true
}

func (toa *TraefikOidcAuth) logAvailableClaims(claims map[string]interface{}) {
	log(toa.Config.LogLevel, LogLevelDebug, "Available claims are:")
	for key, val := range claims {
		log(toa.Config.LogLevel, LogLevelDebug, "  %v = %v", key, val)
	}
}
