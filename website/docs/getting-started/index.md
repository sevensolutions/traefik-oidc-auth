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
      version: "v0.11.0"
```

## Configure Middleware

:::caution
It is highly recommended to change the default encryption-secret by providing your own 32-character secret using the `Secret`-option.
You can generate a random one here: https://it-tools.tech/token-generator?length=32
:::

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
          Secret: "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ" # Please change this secret for your setup
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
# highlight-next-line
kind: Middleware
metadata:
  name: oidc
  namespace: traefik
spec:
  # highlight-start
  plugin:
    traefik-oidc-plugin:  # same key as in the static configuration
      Secret: "urn:k8s:secret:oidc-secret:pluginSecret"
      Provider:
        # You could just write strings here for the values.
        ClientId: "abcd-12345"
        # Or you can reference a Secret in the same namespace as the Middleware.
        # This will resolve to the value of the providerClientSecret key
        # in the secret named oidc-secret.
        ClientSecret: "urn:k8s:secret:oidc-secret:providerClientSecret"
  # highlight-end
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
      # highlight-start
      middlewares:
        - name: oidc
      # highlight-end
      services:
        - kind: Service
          name: whoami
          port: 80
```

  </TabItem>
</Tabs>
