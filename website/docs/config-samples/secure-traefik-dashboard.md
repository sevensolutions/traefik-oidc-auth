# Secure the Traefik Dashboard using OIDC

Traefik comes with a pretty handy dashboard to check if everything is working correctly.
By default, this dashboard is running on a different port for security reasons but you might want to expose it through Traefik itself and secure it with OIDC by using this plugin.

The easiest way to do this is to use a separate subdomain.
The following example uses the domain `127.0.0.1.sslip.io` for simplicity and `traefik.127.0.0.1.sslip.io` as the subdomain for the dashboard.
Please note that we're also using HTTPS here, which is always a good idea.

```yml
http:
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
            UsePkce: true
  
  routers:
    dashboard:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`traefik.127.0.0.1.sslip.io`)"
      service: dashboard@internal
      middlewares: ["oidc-auth@file"]
    dashboard-api:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`traefik.127.0.0.1.sslip.io`) && (PathPrefix(`/api`) || PathPrefix(`/oidc/callback`))"
      service: api@internal
      middlewares: ["oidc-auth@file"]
```

The important things here are:

1. You need to whitelist `https://traefik.127.0.0.1.sslip.io/oidc/callback` as a valid redirect URI in your identity provider.
2. The main dashboard web traffic is routed to `dashboard@internal`.
3. We also need a route for the `/api` path, routing to the `api@internal` service.
4. Make sure you don't forget to route the `/oidc/callback` url to the plugin. This is also done by the second router.
