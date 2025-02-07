---
sidebar_position: 3
---

# Middleware Configuration

## Plugin Config Block

:::caution
It is highly reccomnded to change the default encryption-secret by providing your own 32-character secret using the `Secret`-option.
You can generate a random one here: https://it-tools.tech/token-generator?length=32
:::

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| LogLevel | no | `string` | `WARN` | Defines the logging level of the plugin. Can be one of `DEBUG`, `INFO`, `WARN`, `ERROR`. |
| Secret | no | `string` | `MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ`| A secret used for encryption. Must be a 32 character string. It is strongly suggested to change this. |
| Provider | yes | [`Provider`](#provider) | *none* | Identity Provider Configuration. See *Provider* block. |
| Scopes | no | `string[]` | `["openid", "profile", "email"]` | A list of scopes to request from the IDP. |
| CallbackUri | no | `string` | `/oidc/callback` | Defines the callback url used by the IDP. This needs to be registered in your IDP. This may be either a relative URL or an absolute URL -- see also [Callback URLs](./callback-uri.md) |
| LoginUri | no | `string` | *none* | An optional url, which should trigger the login-flow. The response of every other url is defined by the `UnauthorizedBehavior`-configuration.  |
| PostLoginRedirectUri | no | `string` | *none* | An optional static redirect url where the user should be redirected after login. By default the user will be redirected to the url which triggered the login-flow. |
| LogoutUri | no | `string` | `/logout` | The url which should trigger a logout-flow. |
| PostLogoutRedirectUri | no | `string` | `/` | The url where the user should be redirected after logout. |
| CookieNamePrefix | no | `string` | `TraefikOidcAuth` | Specifies the prefix for all cookies used internally by the plugin. The final names are concatenated using dot-notation. Eg. `TraefikOidcAuth.Session`, `TraefikOidcAuth.CodeVerifier` etc. Please note that this prefix does not apply to *AuthorizationCookieConfig* where the name can be set individually. |
| SessionCookie | no | [`SessionCookieConfig`](#session-cookie) | *none* | SessionCookie Configuration. See *SessionCookieConfig* block. |
| AuthorizationHeader | no | [`AuthorizationHeaderConfig`](#authorization-header) | *none* | AuthorizationHeader Configuration. See *AuthorizationHeaderConfig* block. |
| AuthorizationCookie | no | [`AuthorizationCookieConfig`](#authorization-cookie) | *none* | AuthorizationCookie Configuration. See *AuthorizationCookieConfig* block. |
| UnauthorizedBehavior | no | `string` | `Challenge` | Defines the behavior for unauthenticated requests. `Challenge` means the user will be redirected to the IDP's login page, whereas `Unauthorized` will simply return a 401 status response. |
| Authorization | no | [`Authorization`](#authorization) | *none* | Authorization Configuration. See *Authorization* block. |
| Headers | no | [`Header`](#header) | *none* | Supplies a list of headers which will be attached to the upstream request. See *Header* block. |

## Provider Block {#provider}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Url | no | `string` | *none* | The full URL of the Identity Provider. This is required, if *UrlEnv* is not used. |
| UrlEnv | no | `string` | *none* | The name of an environment variable, containing the full URL of the Identity Provider. This is required, if *Url* is not used. |
| InsecureSkipVerify | no | `bool` | `false` | Disables SSL certificate verification of your provider. It's highly reccomended to provide the real CA bundle via `CABundleFile` instead. So this option should only be used for quick testing. |
| CABundle | no | `string` | *none* | An optional CA certificate bundle provided as a raw string in case you're using self-signed certificates for the provider. Please note that the string needs to represent a valid certificate, including new-lines. In case you cannot provide a multi-line argument you can base64-encode the bundle and provide it with the `base64:` prefix. Eg.: `base64:<your-base64-encoded-bundle>`. |
| CABundleFile | no | `string` | *none* | Specifies the path to an optional CA certificate bundle in case you're using self-signed certificates for the provider. If you're using Docker, make sure the file is mounted into the traefik container. |
| CABundleFileEnv | no | `string` | *none* | The name of an environment variable, containing the CA bundle file. |
| ClientId | no | `string` | *none* | The client id of the application. This is required, if *ClientIdEnv* is not used. |
| ClientIdEnv | no | `string` | *none* | The name of an environment variable, containing the client id. This is required, if *ClientId* is not used. |
| ClientSecret | no | `string` | *none* | The client secret of the application. This is required, if *ClientSecretEnv* is not used and *UsePkce* is false. |
| ClientSecretEnv | no | `string` | *none* | The name of an environment variable, containing the client secret. This is required, if *ClientSecret* and *UsePkce* are not used. |
| UsePkce | no | `bool` | `false`| Enable PKCE. In this case, a client secret is not needed. The following algorithms are supported: *RS*, *EC*, *ES*. |
| ValidateIssuer | no | `bool` | `true` | Specifies whether the `iss` claim in the JWT-token should be validated. |
| ValidIssuer | no | `string` | *discovery document* | The issuer which must be present in the JWT-token. By default this will be read from the OIDC discovery document. |
| ValidIssuerEnv | no | `string` | *none* | The name of an environment variable, containing the valid issuer. This is required, if *ValidIssuer* is not used and ValidateIssuer is enabled. |
| ValidateAudience | no | `bool` | `true` | Specifies whether the `aud` claim in the JWT-token should be validated. |
| ValidAudience | no | `string` | *ClientId* | The audience which must be present in the JWT-token. Defaults to the configured client id. |
| ValidAudienceEnv | no | `string` | *none* | The name of an environment variable, containing the valid audience. This is required, if *ValidAudience* is not used and ValidateAudience is enabled. |
| TokenValidation | no | `string` | `AccessToken` | Specifies which token or method should be used to validate the authentication cookie. Can be either `AccessToken`, `IdToken` or `Introspection`. When using Microsoft EntraID, this will automatically default to `IdToken`. `Introspection` may not work when using PKCE. |

## SessionCookieConfig Block {#session-cookie}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Path | no | `string` | `/` | The path to which the cookie should be assigned to. |
| Domain | no | `string` | *none* | An optional domain to which the cookie should be assigned to. See [Callback URLs](./callback-uri.md) for examples. |
| Secure | no | `bool` | `true` | Whether the cookie should be marked secure. |
| HttpOnly | no | `bool` | `true` | Whether the cookie should be marked http-only. |
| SameSite | no | `string` | `default` | Can be one of `default`, `none`, `lax`, `strict`. |
| MaxAge | no | `int` | `0` | Cookie time-to-live in seconds.  0 (default) is a ephemeral session cookie. |

## AuthorizationHeaderConfig Block {#authorization-header}

By specifying this configuration, a request can send an externally generated access token via this header to authenticate the request.
In this case no session will be created by the middleware. You may also want to set `UnauthorizedBehavior` to `Unauthorized`.

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Name | no | `string` | *none* | The name of the header. |

## AuthorizationCookieConfig Block {#authorization-cookie}

This works exactly the same as [AuthorizationHeaderConfig](#authorization-header), but using a cookie instead of a header. You can also use both.

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Name | no | `string` | *none* | The name of the cookie. |

## Authorization Block {#authorization}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| AssertClaims | no | [`ClaimAssertion[]`](#claim-assertion) | *none* | ClaimAssertion Configuration. See *ClaimAssertion* block. |

## ClaimAssertion Block {#claim-assertion}

If only the `Name` property is set and no additional assertions are defined it is only checked whether there exist any matches for the name of this claim without any verification on their values.
Additionaly, the `Name` field can be any [json path](https://jsonpath.com/). The `Name` gets prefixed with `$.` to match from the root element. The usage of json paths allows for assertions on deeply nested json structures.

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Name | yes | `string` | *none* | The name of the claim in the access token. |
| AnyOf | no | `string[]` | *none* | An array of allowed strings. The user is authorized if any value matching the name of the claim contains (or is) a value of this array. |
| AllOf | no | `string[]` | *none* | An array of required strings. The user is only authorized if any value matching the name of the claim contains (or is) a value of this array and all values of this array are covered in the end. |

It is possible to combine `AnyOf` and `AllOf` quantifiers for one assertion.

:::important
Because the name is being interpreted as jsonpath, you may need to escape some names, if they contain special characters like a colon or minus.
So instead of `Name: "my:zitadel:grants"`, use `Name: "['my:zitadel:grants']"`.
:::

<details>
  <summary>
    <b>Examples</b>
  </summary>
  All of the examples below work on this json structure:

  ```json
  {
      "store": {
        "bicycle": {
          "color": "red",
          "price": 19.95
        },
        "book": [
          {
            "author": "Herman Melville",
            "category": "fiction",
            "isbn": "0-553-21311-3",
            "price": 8.99,
            "title": "Moby Dick"
          },
          {
            "author": "J. R. R. Tolkien",
            "category": "fiction",
            "isbn": "0-395-19395-8",
            "price": 22.99,
            "title": "The Lord of the Rings"
          }
        ],
      }
    }
  ```

  **Example**: Expect array to contain a set of values
  ```yaml
  Name: store.book[*].price
  AllOf: [ 22.99, 8.99 ]
  ```
  This assertion would succeed as the `book` array contains all values specified by the `AllOf` quantifier
  ```yaml
  Name: store.book[*].price
  AllOf: [ 22.99, 8.99, 1 ]
  ```
  This assertion would fail as the `book` array contains no entry for which the `price` is `1`

  **Example**: Expect object key to be any value of a set of values
  ```yaml
  Name: store.bicycle.color
  AnyOf: [ "red", "blue", "green" ]
  ```
  This assertion would succeed as the `store` object contains a `bicycle` object whose `color` is `red`
</details>

## Header Block {#header}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Name | yes | `string` | *none* | The name of the header which should be added to the upstream request. |
| Value | yes | `string` | *none* | The value of the header, which can use [Go-Templates](https://pkg.go.dev/text/template). Please see the info below. |

By using Go-Templates you have access to the following attributes:

| Template | Description |
|---|---|
| `{{ .accessToken }}` | The OAuth Access Token |
| `{{ .idToken }}` | The OAuth Id Token |
| `{{ .claims.* }}` | Replace `*` with the name or path to your desired claim |

:::info
Because [traefik configuration files already support Go-templating](https://doc.traefik.io/traefik/providers/file/#go-templating), you need to *escape* your templates in a weird way. Here are some examples:

```yml
Headers:
  - Name: "Authorization"
    Value: "{{`Bearer {{ .accessToken }}`}}"
  - Name: "X-Oidc-Username"
    Value: "{{`{{ .claims.preferred_username }}`}}"
```

The outer curly braces and backticks are used to escape the inner curly braces.

Note that this *only* applies for configuring Traefik from a YAML file, where it performs its own template expansion.  If you are using the Kubernetes CRDs, you should *not* escape, just template as usual:

```yml
Headers:
  - Name: X-Oidc-Groups-Json-Array
    Value: '[{{with .claims.groups}}{{ range $i, $g := . }}{{if $i}},{{end}}"{{js $g}}"{{end}}{{end}}]'
```
:::
