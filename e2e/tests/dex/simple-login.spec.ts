import { test, expect, Page, Response } from "@playwright/test";
import * as dockerCompose from "docker-compose";
import { configureTraefik } from "../../utils";

//-----------------------------------------------------------------------------
// Test Setup
//-----------------------------------------------------------------------------

test.use({
  ignoreHTTPSErrors: true
});

test.beforeAll("Starting traefik", async () => {
  await configureTraefik(`
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
          Provider:
            UrlEnv: "PROVIDER_URL_HTTP"
            ClientIdEnv: "CLIENT_ID"
            ClientSecretEnv: "CLIENT_SECRET"
            UsePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await dockerCompose.upAll({
    cwd: __dirname,
    log: true
  });
});

test.afterAll("Stopping traefik", async () => {
  await dockerCompose.downAll({
    cwd: __dirname,
    log: true
  });
});

//-----------------------------------------------------------------------------
// Tests
//-----------------------------------------------------------------------------

test("login http", async ({ page }) => {
  await page.goto("http://localhost:9080");

  const response = await login(page, "admin@example.com", "password", "http://localhost:9080");

  expect(response.status()).toBe(200);
});

test("login https", async ({ page }) => {
  await page.goto("https://localhost:9443");

  const response = await login(page, "admin@example.com", "password", "https://localhost:9443");

  expect(response.status()).toBe(200);
});

// Seems like logout is not supported by dex yet :(
// https://github.com/dexidp/dex/issues/1697
// test("logout", async ({ page }) => {
//   await page.goto("http://localhost:9080");

//   const response = await login(page, "admin@example.com", "password", "http://localhost:9080");

//   expect(response.status()).toBe(200);

//   await page.goto("http://localhost:9080/logout");

// });

test("test headers", async ({ page }) => {
  await configureTraefik(`
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
          Provider:
            UrlEnv: "PROVIDER_URL_HTTP"
            ClientIdEnv: "CLIENT_ID"
            ClientSecretEnv: "CLIENT_SECRET"
            UsePkce: false
          Headers:
            - Name: "Authorization"
              Value: "{{\`Bearer: {{ .accessToken }}\`}}"
            - Name: "X-Static-Header"
              Value: "42"

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await page.goto("http://localhost:9080");

  const response = await login(page, "admin@example.com", "password", "http://localhost:9080");

  expect(response.status()).toBe(200);

  const authHeaderExists = await page.locator(`text=Authorization: Bearer: ey`).isVisible();
  expect(authHeaderExists).toBeTruthy();

  const staticHeaderExists = await page.locator(`text=X-Static-Header: 42`).isVisible();
  expect(staticHeaderExists).toBeTruthy();

  // Authorization cookie should not be present in the rendered contents
  const pageText = await page.innerText("html");
  expect(pageText).not.toMatch(/Cookie:\s*(?:^|\s|;)\s*Authorization\s*=\s*[^;\r\n]+/);
});

test("test authorization", async ({ page }) => {
  await configureTraefik(`
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
          Provider:
            UrlEnv: "PROVIDER_URL_HTTP"
            ClientIdEnv: "CLIENT_ID"
            ClientSecretEnv: "CLIENT_SECRET"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin@example.com", "alice@example.com"]

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await page.goto("http://localhost:9080");

  const response = await login(page, "alice@example.com", "password", "http://localhost:9080");

  expect(response.status()).toBe(200);
});

test("test authorization failing", async ({ page }) => {
  await configureTraefik(`
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
          Provider:
            UrlEnv: "PROVIDER_URL_HTTP"
            ClientIdEnv: "CLIENT_ID"
            ClientSecretEnv: "CLIENT_SECRET"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin@example.com", "alice@example.com"]

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await page.goto("http://localhost:9080");

  const response = await login(page, "bob@example.com", "password", "http://localhost:9080/oidc/callback**");

  expect(response.status()).toBe(401);
});

test("login at provider via self signed certificate", async ({ page }) => {
  await configureTraefik(`
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
          Provider:
            UrlEnv: "PROVIDER_URL_HTTPS"
            CABundleFile: "/certificates/bundle/ca_bundle.pem"
            ClientIdEnv: "CLIENT_ID"
            ClientSecretEnv: "CLIENT_SECRET"
            UsePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await page.goto("https://localhost:9443");

  const response = await login(page, "admin@example.com", "password", "https://localhost:9443");

  expect(response.status()).toBe(200);
});

//-----------------------------------------------------------------------------
// Helper functions
//-----------------------------------------------------------------------------

async function login(page: Page, username: string, password: string, waitForUrl: string): Promise<Response> {
  await page.locator(':text("Log in with Email")').click();

  await page.locator("#login").fill(username);
  await page.locator("#password").fill(password);

  const responsePromise = page.waitForResponse(waitForUrl);

  await page.locator('button:text("Login")').click();

  const response = await responsePromise;

  return response;
}
