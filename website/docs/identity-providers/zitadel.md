---
sidebar_position: 2
---

# ZITADEL

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

[Website Link](https://zitadel.com/)

## Setup ZITADEL

You can register for [ZITADEL Cloud](https://zitadel.com/signin) or [self host](https://zitadel.com/docs/self-hosting/deploy/overview).

1. Create a new *Project* in the ZITADEL Admin Console.
2. Within the Project create a new *Application*. This depends on whether you want to use PKCE or not.

<Tabs groupId="type">
  <TabItem value="pkce" label="With PKCE">
    3. Click *New* in the Applications-section.
    4. Enter a name for the Application and select the type *Web*.
    5. In the next step, select *PKCE* as authentication method.
  </TabItem>
  <TabItem value="no-pkce" label="Without PKCE">
    3. Click *New* in the Applications-section.
    4. Enter a name for the Application and select the type *Web*.
    5. In the next step, select *CODE* as authentication method.
  </TabItem>
</Tabs>

6. For the *Redirect URIs* specify the public URL of your application and append the path `/oidc/callback`.  
Eg.: `https://my-app.mydomain.com/oidc/callback`.

:::tip
Make sure you're using HTTPS. If you want to use an HTTP url, you need to enable the *Development Mode*.
:::

7. Within the new Application, navigate to *Token Settings* and change the *Auth Token Type* to *JWT*. This is important!

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

## Role Based Authorization

ZITADEL has the concept of *Roles* within a Project.

The easiest way to ensure that only users with a role are allowed to authenticate is to select the three options within the ZITADEL project.
- Assert Roles on Authentication
- Check authorization on Authentication
- Check for Project on Authentication

This type of authorization is handled completely within ZITADEL but all users are allowed which have at least one role assigned.

For a more granular authorization you can use the Authorization-feature of *traefik-oidc-auth*.

1. First, we need to ensure the roles are mapped within the tokens. Navigate to the *Token Settings* of your application and enable *Add user roles to the access token*.
2. In the top menu of the ZITADEL console navigate to *Actions*
3. Add a new Script
4. Enter the name `flatRoles` and paste the following script:
```js
function flatRoles(ctx, api) {
  if (ctx.v1.user.grants === undefined || ctx.v1.user.grants.count == 0) {
    return;
  }
    
  let roles = [];
  for(const claim of ctx.v1.user.grants.grants) {
    for(const role of claim.roles)
      roles.push(role);
  }
    
  api.v1.claims.setClaim('roles', roles);
}
```

:::caution
The script's name has to match the function name.
:::

5. Scroll down to the *Flows* section and select the *Complement Token* flow type.
6. Click *Add trigger* and select trigger type *Pre access token creation*.
7. Assign your `flatRoles` action and Save.

With this configuration, the access token should now contain a flat list of `roles`, containing all roles, assigned to the user.
We can now easily assert these roles with the following *traefik-oidc-auth* configuration:

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
          # highlight-start
          Authorization:
            AssertClaims:
              - Name: roles
                AnyOf: ["admin", "media"]
          # highlight-end
```
