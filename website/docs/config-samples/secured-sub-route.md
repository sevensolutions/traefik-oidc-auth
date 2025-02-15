# Secure a sub-route only

You may want to secure a sub-route only, while keeping all other routes public.
This can be achieved by simply using multiple traefik-routers.

Lets say we want to secure everything below the `/secure`-path and everything else should be public.  
Here is an example config:

```yaml
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          Secret: "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ" # Please change this secret for your setup
          Provider:
            UrlEnv: "PROVIDER_URL"
            ClientIdEnv: "CLIENT_ID"
            ClientSecretEnv: "CLIENT_SECRET"
          SessionCookie:
            Path: "/secure" # Optional. If set, the cookie will only be sent to the /secure path.
          
  routers:
    whoami-callback:
      entryPoints: ["web"]
      rule: "HostRegexp(`.+`) && PathPrefix(`/oidc/callback`)"
      priority: 100
      service: noop@internal
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["web"]
      rule: "HostRegexp(`.+`) && PathPrefix(`/secure`)"
      priority: 50
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-public:
      entryPoints: ["web"]
      rule: "HostRegexp(`.+`)"
      priority: 10
      service: whoami
```

The important things here are:

1. We need to ensure that the OIDC-callback reaches our middleware. So we need to setup a route, matching the callback url and ensure it's using our middleware. This is done by the first router and we've also specified a higher priority. The service doesn't matter, because the callback is handled by the middleware, so it never reaches the service. Thats why we just use `noop@internal`.
2. The second router matches our `/secure`-path and is also using the middleware. Because the session cookie from our middleware is only needed on this path, we've also changed the `SessionCookie.Path` on the middleware to `/secure`. This is not needed and only works, if you're securing just a single sub-route. It's just an optimization that the cookie will only be sent to the `/secure`-path and not to the public one.
3. The last router matches everything else and is bypassing the middleware, simply by not using it.

:::tip
You can also combine the first and second router by using an OR, if you want.  
```yaml
rule: "HostRegexp(`.+`) && (PathPrefix(`/secure`) || PathPrefix(`/oidc/callback`))"
```
:::
