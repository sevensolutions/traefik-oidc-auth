---
sidebar_position: 5
---

# Authorization

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

As soon as a user is authenticated it is allowed to use the application, secured by *traefik-oidc-auth*.
But you may have multiple applications and you may want to specify a more granular definition of who is allowed to access which application.
This can be achieved using the plugin's `ClaimAssertion`s.

When a user is authenticated, an `access_token` and an `id_token` is returned by the identity provider, a *session* is created and these tokens are stored within that session. By default the `access_token` is used but you can use the other one by setting [`TokenValidation`](./middleware-configuration.md#provider) to `IdToken`.

Both tokens are [*Json Web Tokens (JWT)*](https://jwt.io/) which can be decoded and made human-readable using [online tools](https://jwt.io/).
When being decoded they're represented as a JSON-object where every property is called a *Claim*.

Here is an example of a decoded token:

```json
{
  "exp": 1749314471,
  "iat": 1749314411,
  "auth_time": 1749314411,
  "jti": "onrtac:3b5c0b13-8471-4e98-a329-226d6c1d0b78",
  "iss": "http://127-0-0-1.sslip.io:8000/realms/master",
  "aud": [
    "master-realm",
    "account"
  ],
  "sub": "c0d6f5c3-d05f-474d-bf06-f590b0a397ad",
  "typ": "Bearer",
  "azp": "traefik",
  "sid": "758810d0-6be1-43a3-8c2b-7ae69e5eba00",
  "acr": "1",
  "realm_access": {
    "roles": [
      "create-realm",
      "default-roles-master",
      "offline_access",
      "admin",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "master-realm": {
      "roles": [
        "view-realm",
        "view-identity-providers",
        "query-groups"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid email profile",
  "email_verified": false,
  "preferred_username": "admin"
}
```

:::tip
Every identity provider returns tokens with a default set of claims. Some of them are standardized while some are not.  
Some identity providers also allow you to *map* different properties into your token but you need to refer to your IDP's documentation for how to do that.
You can also check out the [Identity Providers section](../identity-providers/index.md) for more information and some config examples.
:::

## How it works

Every authorization rule is expressed by a claim-assertion using the `AssertClaims`-property.
These rules need to contain a name-selector and an optional `AllOf` or `AnyOf` quantifier.
If only the name is set without a quantifier, the rule only checks for presence of the claim without further validating it's value.
It is also possible to combine the `AnyOf` and `AllOf` quantifiers in one assertion.

:::important
Because the name is being interpreted as [json path](https://jsonpath.com/), you may need to escape some names, if they contain special characters like a colon or minus.
So instead of `Name: "my:zitadel:grants"`, use `Name: "['my:zitadel:grants']"`.
:::

:::tip
If the user is not authorized, all claims, contained in the token, are printed in the console if the [`LogLevel`](./middleware-configuration.md) is set to `DEBUG`. This may help you to know which claims exist in your token.
:::

Here is a commonly used example configuration on how to only allow *admin* or *media* users, based on the `roles` claim.  
As you can see, the name selects the `roles` claim from the token and checks if the value matches *AnyOf* the given values.

<Tabs groupId="examples">
<TabItem value="config" label="⚙ Configuration">

**YAML**
```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://your-idp.com"
            ClientId: "<YourClientId>"
            UsePkce: true
          Scopes: ["openid", "profile", "email"]
          # highlight-start
          Authorization:
            AssertClaims:
              - Name: roles
                AnyOf: ["admin", "media"]
          # highlight-end
```

**Docker Labels**
```
traefik.http.middlewares.oidc-auth.traefik-oidc-auth.provider.authorization.assertClaims[0].name=roles"
traefik.http.middlewares.oidc-auth.traefik-oidc-auth.provider.authorization.assertClaims[0].anyOf=admin,media"
```

</TabItem>
<TabItem value="authorized-token" label="✅ Authorized Token">

```json
{
  "exp": 1749314471,
  "iat": 1749314411,
  "auth_time": 1749314411,
  "jti": "onrtac:3b5c0b13-8471-4e98-a329-226d6c1d0b78",
  "iss": "http://127-0-0-1.sslip.io:8000/realms/master",
  "aud": [
    "master-realm",
    "account"
  ],
  "sub": "c0d6f5c3-d05f-474d-bf06-f590b0a397ad",
  "typ": "Bearer",
  "azp": "traefik",
  "sid": "758810d0-6be1-43a3-8c2b-7ae69e5eba00",
  "acr": "1",
  "scope": "openid email profile",
  "email_verified": false,
  "preferred_username": "admin",
  // highlight-next-line
  "roles": ["admin"]
}
```

</TabItem>
<TabItem value="unauthorized-token" label="❌ Unauthorized Token">

```json
{
  "exp": 1749314471,
  "iat": 1749314411,
  "auth_time": 1749314411,
  "jti": "onrtac:3b5c0b13-8471-4e98-a329-226d6c1d0b78",
  "iss": "http://127-0-0-1.sslip.io:8000/realms/master",
  "aud": [
    "master-realm",
    "account"
  ],
  "sub": "c0d6f5c3-d05f-474d-bf06-f590b0a397ad",
  "typ": "Bearer",
  "azp": "traefik",
  "sid": "758810d0-6be1-43a3-8c2b-7ae69e5eba00",
  "acr": "1",
  "scope": "openid email profile",
  "email_verified": false,
  "preferred_username": "admin",
  // highlight-next-line
  "roles": ["user"]
}
```

</TabItem>
</Tabs>

## More complicated examples

Here are some more complex examples based on the following json structure. This json doesn't represent an actual JWT but I hope you get the idea.

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

## Custom Error Page

If a user is authenticated but unauthorized, a default error page is showen and a status code 403 - Forbidden is returned.
You can customize this page by providing your own HTML-file as shown below:

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://your-idp.com"
            ClientId: "<YourClientId>"
            UsePkce: true
          Scopes: ["openid", "profile", "email"]
          # highlight-start
          ErrorPages:
            Unauthorized:
              FilePath: "/opt/traefik/error-pages/unauthorized.html"
          # highlight-end
```

:::note
If you're running traefik in a docker container, make sure you copy or mount this file into the container.
:::
:::important
This html file needs to be self-contained which means all CSS and JS must be inlined or loaded from a CDN.
:::
