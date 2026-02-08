# Logto

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

[Website Link](https://logto.io/)

## Setup Logto

You can register for [Logto Cloud](https://auth.logto.io/register) or [self host](https://docs.logto.io/logto-oss/get-started-with-oss).

1. Create a new *Application* of type *Third-party app (Traditional web)* in the Logto Admin Console.
2. Within the Project configure the *Redirect URIs*.
Specify the public URL of your application and append the path `/oidc/callback`.  
Eg.: `https://my-app.mydomain.com/oidc/callback`.
3. Enter the same for *Post sign-out redirect URIs*.

:::tip
If you want to use refresh tokens, you may need to enable the option *Always issue refresh token* in the Logto console.
It seems that Logto doesn't honor the `offline_access` scope.
:::

## Middleware Configuration

:::tip
You will find the client id and secret in the *Endpoints & Credentials* sections within Logto.
The client id is called *App ID* in Logto.
:::

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://login.my-logto.com/oidc"
            ClientId: "<YourAppId>"
            ClientSecret: "<YourClientSecret>"
            UsePkce: true
          Scopes: ["openid", "profile", "email"]
```
