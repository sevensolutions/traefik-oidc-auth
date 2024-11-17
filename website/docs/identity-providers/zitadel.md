---
sidebar_position: 2
---

# ZITADEL

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

[Website Link](https://zitadel.com/)

## Setup ZITADEL

<Tabs groupId="type">
  <TabItem value="pkce" label="With PKCE">
  
  </TabItem>
  <TabItem value="secret" label="Without PKCE">
  
  </TabItem>
</Tabs>

## Middleware Configuration

<Tabs groupId="type">
  <TabItem value="pkce" label="With PKCE">
  
```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://your-instance.zitadel.cloud"
            ClientId: "<YourClientId>"
            UsePkce: true
          Scopes: ["openid", "profile", "email"]
```

  </TabItem>
  <TabItem value="secret" label="Without PKCE">
  
```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://your-instance.zitadel.cloud"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
          Scopes: ["openid", "profile", "email"]
```

  </TabItem>
</Tabs>
