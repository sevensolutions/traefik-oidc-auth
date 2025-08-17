---
sidebar_position: 5
---

# Microsoft Entra ID

[Website Link](https://learn.microsoft.com/de-de/entra/identity/)

## Setup Entra ID

1. Log in to your Azure Portal and navigate to *Microsoft Entra ID*.
2. In the left navigation panel go to *Manage > App registrations*.
3. Click *New Registration* and specify a name.
4. Select the appropriate option for the authorized users.
4. Scroll down to *Redirect URI (optional)* and specify the public URL of your application and append the path `/oidc/callback`.  
Eg.: `https://my-app.mydomain.com/oidc/callback`.

## Middleware Configuration

:::tip
You will find the client id and tenant-id on the *Overview* page of your *App registration*. They're called *Application (client) ID* and *Directory (tenant) ID* or similar.
The client secret can be found on the left side under *Manage > Certificates & secrets*. Be sure you copy the Value, not the Secret ID.
:::

:::caution
Make sure you use the EntraID url ending with `/v2.0`. It should be in the form `https://login.microsoftonline.com/<YourTenantId>/v2.0`.
The old url will not work.
:::

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://login.microsoftonline.com/<YourTenantId>/v2.0"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
          Scopes: ["openid", "profile", "email"]
```
