---
sidebar_position: 3
---

# Kanidm

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

[Website Link](https://github.com/kanidm/kanidm)

## Setup Kanidm

To create or manage OAuth2 clients, you should use [kanidm client](https://kanidm.github.io/kanidm/stable/client_tools.html) and be a member of the `system_admins` or `idm_hp_oauth2_manage_priv` groups.

1. Create a new OAuth2 client
   ```shell
   kanidm system oauth2 create <client_id> <displayname> <landing page url>
   ```
2. Update a scope map to be able to use the client within OpenID Connect (OIDC)
   ```shell
   kanidm system oauth2 update-scope-map <client_id> <group_name> openid
   ```
   You might also want to include other scopes here, e.g. `profile`, `email` or `groups`
   ```shell
   kanidm system oauth2 update-scope-map <client_id> <group_name> openid profile email groups
   ```
   You can use `idm_all_persons` as a `<group_name>` if you are fine with all receiving having access to the client.
3. Add a redirect URL, where you specify the public URL of your application and append the path `/oidc/callback`
   ```shell
   kanidm system oauth2 add-redirect-url <client_id> https://login.example.com/oidc/callback
   ```
   You might need to add all your subdomains where you plan to use this middleware or use [Absolute URL](../getting-started/callback-uri.md#absolute-url) configuration.
4. Let's verify what we have now
   ```shell
   kanidm system oauth2 get <client_id>
   ```
   In the example below `traefik-oauth2` is the `<client_id>`
   ```yaml
    class: account
    class: memberof
    class: oauth2_resource_server
    class: oauth2_resource_server_basic
    class: object
    directmemberof: idm_all_accounts@example.com
    displayname: Traefik OAuth
    es256_private_key_der: private_binary
    memberof: idm_all_accounts@example.com
    name: traefik-oauth2
    oauth2_allow_insecure_client_disable_pkce: true
    oauth2_rs_basic_secret: hidden
    oauth2_rs_origin: https://login.example.com/oidc/callback
    oauth2_rs_origin_landing: https://login.example.com/
    oauth2_rs_scope_map: idm_all_persons@example.com: {"email", "groups", "openid", "profile"}
    oauth2_rs_token_key: hidden
    oauth2_strict_redirect_uri: true
    spn: traefik-oauth2@example.com
    uuid: f1f4e707-832e-4beb-ba12-9410b883dddf
   ```

You will find all Kanidm configuration options in [the documentation](https://kanidm.github.io/kanidm/stable/integrations/oauth2.html).

:::tip
Before you start, make sure your Kanidm has a valid (and not self-signed) TLS certificate and `idm.example.com` is accessible from the Traefik container/host.
:::

## Middleware Configuration

:::tip
To display the client's secret, use `kanidm system oauth2 show-basic-secret <client_id>`
:::

<Tabs groupId="type">
  <TabItem value="relative-secure" label="Relative URL with PKCE">
  
```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://idm.example.com/oauth2/openid/<client_id>"
            ClientId: "<client_id>"
            TokenValidation: "IdToken"
            UsePkce: true
          Scopes: ["openid", "profile"]
```

  </TabItem>
  <TabItem value="relative" label="Relative URL without PKCE">
  
```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://idm.example.com/oauth2/openid/<client_id>"
            ClientId: "<client_id>"
            ClientSecret: "<client_secret>"
            TokenValidation: "IdToken"
          Scopes: ["openid", "profile"]
```

  </TabItem>
  <TabItem value="absolute" label="Absolute URL without PKCE and Forward Auth headers">
  
```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          CallbackUri: "https://login.example.com/oidc/callback"
          SessionCookie:
            Domain: ".example.com"
          Provider:
            Url: "https://idm.example.com/oauth2/openid/<client_id>"
            ClientId: "<client_id>"
            ClientSecret: "<client_secret>"
            TokenValidation: "IdToken"
            UsePkce: false
          Scopes: ["openid", "profile", "email", "groups"]
          Headers:
            - Name: "Remote-User"
              Value: "{{`{{ .claims.preferred_username }}`}}"
            - Name: "Remote-Email"
              Value: "{{`{{ .claims.email }}`}}"
            - Name: "Remote-Groups"
              Value: "{{`{{ .claims.groups }}`}}"
            - Name: "Remote-Name"
              Value: "{{`{{ .claims.name }}`}}"

  routers:
    auth:
      rule: "Host(`login.example.com)"
      service: noop@internal
      middlewares: ["oidc-auth@file"]
```

  </TabItem>
</Tabs>

:::note
You need to set `TokenValidation` to `IdToken` to populate claims. Otherwise, they do not include any scopes.
:::

:::note
Kanidm enforces PKCE by default. To disable this behaviour use `kanidm system oauth2 warning-insecure-client-disable-pkce <client_id>`
:::
