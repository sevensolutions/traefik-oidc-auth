---
sidebar_position: 1
---

# Identity Providers

This documentation section will give you an overview of the support-status of well known identity providers.
Select a provider to see detailed setup instructions.

:::info
If you have tested a new Identity Provider, not mentioned here already, please open a PR and document it 🙏.

[![Open in Codeflow](https://developer.stackblitz.com/img/open_in_codeflow.svg)](https://pr.new/sevensolutions/traefik-oidc-auth)
:::

| Provider | Status | Notes |
|---|---|---|
| [ZITADEL](./zitadel.md) | ✅ | |
| [Kanidm](./kanidm.md) | ✅ | See [GH-12](https://github.com/sevensolutions/traefik-oidc-auth/issues/12) |
| [Keycloak](./keycloak.md) | ✅ | |
| [Microsoft Entra ID](./entra-id.md) | ✅ | |
| [HashiCorp Vault](https://www.vaultproject.io/) | ❌ | See [GH-13](https://github.com/sevensolutions/traefik-oidc-auth/issues/13) |
| [Authentik](./authentik.md) | ✅ | |
| [Pocket ID](./pocket-id.md) | ✅ | |
| [GitHub](https://github.com) | ❌ | GitHub doesn't seem to support OIDC, only plain OAuth. |

✅ Supported | 🧐 Untested (See Notes) | ❌ Not Supported
