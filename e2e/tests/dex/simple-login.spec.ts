import { test, expect, Page, Response } from "@playwright/test";
import * as dockerCompose from "docker-compose";
import { configureTraefik } from "../../utils";
import fs from "fs";
import path from "path";

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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
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

test.afterEach("Traefik logs on test failure", async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    console.log(`${testInfo.title} failed, here are Traefik logs:`);
    console.log(await dockerCompose.logs("traefik", { cwd: __dirname }));
    console.log(await dockerCompose.logs("dex-https", { cwd: __dirname }));
  }
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
  await expectGotoOkay(page, "http://localhost:9080");

  const response = await login(page, "admin@example.com", "password", "http://localhost:9080");

  expect(response.status()).toBe(200);
});

test("login https", async ({ page }) => {
  await expectGotoOkay(page, "https://localhost:9443");

  const response = await login(page, "admin@example.com", "password", "https://localhost:9443");

  expect(response.status()).toBe(200);
});

// Seems like logout is not supported by dex yet :(
// https://github.com/dexidp/dex/issues/1697
// test("logout", async ({ page }) => {
//   await expectGotoOkay(page, "http://localhost:9080");

//   const response = await login(page, "admin@example.com", "password", "http://localhost:9080");

//   expect(response.status()).toBe(200);

//   await page.goto("http://localhost:9080/logout");

// });

test("test two services is seamless", async ({ page }) => {
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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          Headers:
            - Name: "Authorization"
              Value: "{{\`Bearer: {{ .accessToken }}\`}}"
            - Name: "X-Static-Header"
              Value: "42"

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "Host(\`localhost\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    other:
      entryPoints: ["web"]
      rule: "Host(\`localhost\`) && Path(\`/other\`)"
      service: noop@internal  # serves 418 I'm A Teapot
      middlewares: ["oidc-auth@file"]

`);

  await expectGotoOkay(page, "http://localhost:9080/");

  const response = await login(page, "admin@example.com", "password", "http://localhost:9080");

  expect(response.status()).toBe(200);

  const otherSvcResp = await page.goto("http://localhost:9080/other");
  expect(otherSvcResp!.status()).toBe(418);
  expect(otherSvcResp!.request().redirectedFrom()).toBeNull();
});


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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
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

  await expectGotoOkay(page, "http://localhost:9080");

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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
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

  await expectGotoOkay(page, "http://localhost:9080");

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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
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

  await expectGotoOkay(page, "http://localhost:9080");

  const response = await login(page, "bob@example.com", "password", "http://localhost:9080/oidc/callback**");

  expect(response.status()).toBe(403);

  expect(await response.text()).toContain("It seems like your account is not allowed to access this resource.");
});

test("login at provider via self signed certificate from file", async ({ page }) => {
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
            Url: "\${PROVIDER_URL_HTTPS}"
            CABundleFile: "/certificates/bundle/ca_bundle.pem"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
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

  await expectGotoOkay(page, "https://localhost:9443");

  const response = await login(page, "admin@example.com", "password", "https://localhost:9443");

  expect(response.status()).toBe(200);
});

test("login at provider via self signed inline certificate", async ({ page }) => {
  const certBundle = fs.readFileSync(path.join(__dirname, "./certificates/bundle/ca_bundle.pem"));
  const base64CertBundle = certBundle.toString("base64");

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
            Url: "\${PROVIDER_URL_HTTPS}"
            CABundle: "base64:${base64CertBundle}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
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

  await expectGotoOkay(page, "https://localhost:9443");

  const response = await login(page, "admin@example.com", "password", "https://localhost:9443");

  expect(response.status()).toBe(200);
});

test("access app with bypass rule", async ({ page }) => {
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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          BypassAuthenticationRule: "Header(\`MY-HEADER\`, \`123\`)"

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  // The first test should bypass authentication and directly return the whoami page.
  await page.route("http://localhost:9080/**/*", route => {
    const headers = route.request().headers();
    headers["MY-HEADER"] = "123";

    route.continue({ headers });
  });
  
  await page.goto("http://localhost:9080/test1");

  await expect(page.getByText(/My-Header: 123/i)).toBeVisible();

  // The second test should return a redirect to the IDP, because the header doesn't match.
  await page.route("http://localhost:9080/**/*", route => {
    const headers = route.request().headers();
    headers["MY-HEADER"] = "456";

    route.continue({ headers });
  });

  const response = await page.goto("http://localhost:9080/test2");

  expect(response?.url()).toMatch(/http:\/\/localhost:5556\/dex\/auth.*/);
});

test("external authentication", async ({ page }) => {
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
                Url: "\${PROVIDER_URL_HTTP}"
                ClientId: "\${CLIENT_ID}"
                ClientSecret: "\${CLIENT_SECRET}"
                UsePkce: false
              AuthorizationHeader:
                Name: "CustomAuth"
              AuthorizationCookie:
                Name: "CustomAuth"
              UnauthorizedBehavior: "Unauthorized"
    
      routers:
        whoami:
          entryPoints: ["web"]
          rule: "HostRegexp(\`.+\`)"
          service: whoami
          middlewares: ["oidc-auth@file"]
  `);

  const token = await loginAndGetToken(page, "admin@example.com", "password");

  const response1 = await fetch("http://localhost:9080", {
    method: "GET"
  });

  expect(response1.status).toBe(401);

  const response2 = await fetch("http://localhost:9080", {
    method: "GET",
    "headers": {
      CustomAuth: token
    }
  });

  expect(response2.status).toBe(200);

  const response3 = await fetch("http://localhost:9080", {
    method: "GET",
    "headers": {
      CustomAuth: "wrong value"
    }
  });

  expect(response3.status).toBe(401);

  const response4 = await fetch("http://localhost:9080", {
    method: "GET",
    "headers": {
      Cookie: `CustomAuth=${token}`
    }
  });

  expect(response4.status).toBe(200);

  const response5 = await fetch("http://localhost:9080", {
    method: "GET",
    "headers": {
      Cookie: `CustomAuth=wrong-value`
    }
  });

  expect(response5.status).toBe(401);
});

test("external authentication with authorization rules", async ({ page }) => {
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
                Url: "\${PROVIDER_URL_HTTP}"
                ClientId: "\${CLIENT_ID}"
                ClientSecret: "\${CLIENT_SECRET}"
                UsePkce: false
              AuthorizationHeader:
                Name: "CustomAuth"
              UnauthorizedBehavior: "Unauthorized"
              Authorization:
                AssertClaims:
                  - Name: name
                    AnyOf: ["admin", "alice"]
    
      routers:
        whoami:
          entryPoints: ["web"]
          rule: "HostRegexp(\`.+\`)"
          service: whoami
          middlewares: ["oidc-auth@file"]
  `);

  const aliceToken = await loginAndGetToken(page, "alice@example.com", "password");

  const response1 = await fetch("http://localhost:9080", {
    method: "GET",
    "headers": {
      CustomAuth: aliceToken
    }
  });

  // Alice should be authorized, based on AssertClaims
  expect(response1.status).toBe(200);

  const bobToken = await loginAndGetToken(page, "bob@example.com", "password");

  const response2 = await fetch("http://localhost:9080", {
    method: "GET",
    "headers": {
      CustomAuth: bobToken
    }
  });

  // but bob should not be authorized
  expect(response2.status).toBe(403);
});

test("test authorization custom error page", async ({ page }) => {
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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin@example.com", "alice@example.com"]
          ErrorPages:
            Unauthorized:
              FilePath: "/data/customUnauthorizedPage.html"

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await expectGotoOkay(page, "http://localhost:9080");

  const response = await login(page, "bob@example.com", "password", "http://localhost:9080/oidc/callback**");

  expect(response.status()).toBe(403);

  expect(await response.text()).toContain("CUSTOM ERROR PAGE");
});

test("test authorization error redirect", async ({ page }) => {
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
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin@example.com", "alice@example.com"]
          ErrorPages:
            Unauthorized:
              RedirectTo: "https://httpbin.org/unauthorized"

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(\`.+\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await expectGotoOkay(page, "http://localhost:9080");

  const response = await login(page, "bob@example.com", "password", "http://localhost:9080/oidc/callback**");

  expect(response.status()).toBe(302);
  expect(await response.headerValue("Location")).toBe("https://httpbin.org/unauthorized");
});

test("test CheckOnEveryRequest", async ({ page }) => {
   await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    auth:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          Provider:
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["bob@example.com", "alice@example.com"]
            CheckOnEveryRequest: true
    auth-bob:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          Provider:
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["bob@example.com"]
            CheckOnEveryRequest: true

    auth-alice:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          Provider:
            Url: "\${PROVIDER_URL_HTTP}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["alice@example.com"]
            CheckOnEveryRequest: true

  routers:
    oidc-callback:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/oidc/callback\`)"
      service: noop@internal
      middlewares: ["auth"]

    whoami-bob:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/bob\`)"
      service: whoami
      middlewares: ["auth-bob"]

    whoami-alice:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/alice\`)"
      middlewares: ["auth-alice"]
      service: whoami
`);
  await expectGotoOkay(page, "http://localhost:9080/alice");

  const response = await login(page, "alice@example.com", "password", "http://localhost:9080/alice");
  expect(response.status()).toBe(200);

  await expectGotoOkay(page, "http://localhost:9080/alice");

  const respBob = await page.goto("http://localhost:9080/bob");
  expect(respBob?.status()).toBe(403);

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

async function expectGotoOkay(page: Page, url: string) {
  const response = await page.goto(url); // follows redirects
  expect(response?.status()).toBe(200);
}

async function loginAndGetToken(page: Page, username: string, password: string): Promise<string> {
  // This method is a bit hacky but i don't know a better way jet.
  // It intercepts the auth code and then exchanges it for a token.
  page.goto("http://localhost:5556/dex/auth?client_id=traefik&redirect_uri=http%3A%2F%2Flocalhost%3A9080%2Foidc%2Fcallback&response_type=code&scope=openid+profile+email&state=MTIz")

  const response = await login(page, username, password, "http://localhost:9080/oidc/callback*");

  const url = response.url();
  
  const p1 = url.indexOf("code=") + 5;
  const p2 = url.indexOf("state=", p1) - 1;

  const code = url.substring(p1, p2);
  
  const tokenResponse = await fetch("http://localhost:5556/dex/token", {
    method: "POST",
    headers:{
      "Content-Type": "application/x-www-form-urlencoded"
    },    
    body: new URLSearchParams({
        "grant_type": "authorization_code",
        "code": code,
        "client_id": "traefik",
        "client_secret": "ZXhhbXBsZS1hcHAtc2VjcmV0",
        "scope": "openid profile email",
        "redirect_uri": "http://localhost:9080/oidc/callback",
        "state": "MTIz"
    })
  });

  const tokens = await tokenResponse.json();
  return tokens.access_token;
}
