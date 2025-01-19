---
sidebar_position: 1
---

# Getting Started

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

## Configure the Plugin

Enable the plugin in your traefik configuration.

```yml
experimental:
  plugins:
    traefik-oidc-auth:
      moduleName: "github.com/sevensolutions/traefik-oidc-auth"
      version: "v0.5.0"
```

## Configure Middleware

<Tabs>
  <TabItem value="yaml" label="YAML" default>

This is an example using [YAML file](https://doc.traefik.io/traefik/providers/file/) config

```yml
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
  # highlight-start
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://<YourIdentityProviderUrl>"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
            #UsePkce: true # Or use PKCE if your Provider supports this
          Scopes: ["openid", "profile", "email"]
    # highlight-end

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(`.+`)"
      service: whoami
      # highlight-next-line
      middlewares: ["oidc-auth"]
```

  </TabItem>
  <TabItem value="k8s" label="Kubernetes">

This is an example using [Kubernetes IngressRoute CRD](https://doc.traefik.io/traefik/providers/kubernetes-crd/) config

```yml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc
  namespace: traefik
spec:
  plugin:
    traefik-oidc-plugin:  # same key as in the static configuration
      Provider:
        # You could just write strings here for the values.
        ClientId: "abcd-12345"
        # Or you can reference a Secret in the same namespace as the Middleware.
        # This will resolve to the value of the providerClientSecret key
        # in the secret named oidc-secret.
        ClientSecret: "urn:k8s:secret:oidc-secret:providerClientSecret"
      Secret: "urn:k8s:secret:oidc-secret:pluginSecret"
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: whoami
  namespace: traefik
spec:
  routes:
    - kind: Rule
      match: Host(`whoami.mycluster.com`)
      middlewares:
        - name: oidc
      services:
        - kind: Service
          name: whoami
          port: 80
```

  </TabItem>
</Tabs>
