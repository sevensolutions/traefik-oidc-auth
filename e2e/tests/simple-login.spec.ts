import { test, expect } from '@playwright/test';

test.use({
  ignoreHTTPSErrors: true,
  headless: false
});

test('login http', async ({ page }) => {
  await page.goto("http://localhost:9080");

  await page.waitForURL("http://localhost:5556/dex/auth**");

  await page.locator(':text("Log in with Email")').click();

  await page.locator("#login").fill("admin@example.com");
  await page.locator("#password").fill("password");

  const responsePromise = page.waitForResponse("http://localhost:9080");

  await page.locator('button:text("Login")').click();

  const response = await responsePromise;

  expect(response.status()).toBe(200);
});

test('login https', async ({ page }) => {
  await page.goto("https://localhost:9443");

  await page.waitForURL("http://localhost:5556/dex/auth**");

  await page.locator(':text("Log in with Email")').click();

  await page.locator("#login").fill("admin@example.com");
  await page.locator("#password").fill("password");

  const responsePromise = page.waitForResponse("https://localhost:9443");

  await page.locator('button:text("Login")').click();

  const response = await responsePromise;

  expect(response.status()).toBe(200);
});
