---
sidebar_position: 3
---

# Middleware Configuration

## Plugin Config Block

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Secret | no | `string` | `MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ`| A secret used for encryption. Must be a 32 character string. It is strongly suggested to change this. |
| Provider | yes | `Provider` | *none* | Identity Provider Configuration. See *Provider* block. |
| Scopes | no | `string[]` | `["openid", "profile", "email"]` | A list of scopes to request from the IDP. |
| CallbackUri | no | `string` | `/oidc/callback` | Defines the callback url used by the IDP. This needs to be registered in your IDP. |
| LoginUri | no | `string` | *none* | An optional url, which should trigger the login-flow. By default every url triggers a login-flow, if the user is not already logged in. If you set this to eg. `/login`, only this url will trigger a login-flow while all other requests return *Unauthorized*.  |
| PostLoginRedirectUri | no | `string` | *none* | An optional static redirect url where the user should be redirected after login. By default the user will be redirected to the url which triggered the login-flow. |
| LogoutUri | no | `string` | `/logout` | The url which should trigger a logout-flow. |
| PostLogoutRedirectUri | no | `string` | `/` | The url where the user should be redirected after logout. |
| Authorization | no | `Authorization` | *none* | Authorization Configuration. See *Authorization* block. |
| Headers | no | `Headers` | *none* | Header Configuration. See *Headers* block. |

## Provider Block

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Url | no | `string` | *none* | The full URL of the Identity Provider. This is required, if *UrlEnv* is not used. |
| UrlEnv | no | `string` | *none* | The name of an environment variable, containing the full URL of the Identity Provider. This is required, if *Url* is not used. |
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

## Authorization Block

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| AssertClaims | no | `ClaimAssertion[]` | *none* | ClaimAssertion Configuration. See *ClaimAssertion* block. |

## ClaimAssertion Block

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

## Headers Block

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| MapClaims | no | `ClaimHeader[]` | *none* | A list of claims which should be mapped as headers when the request will be sent to the upstream. See *ClaimHeader* block. |

## ClaimHeader Block

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| Claim | yes | `string` | *none* | The name of the claim |
| Header | yes | `string` | *none* | The name of the header which should receive the claim value. |
