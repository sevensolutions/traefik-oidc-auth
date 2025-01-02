import { test, expect } from '@playwright/test';

test.use({
  ignoreHTTPSErrors: true,
  headless: false
});

test('login', async ({ page }) => {
  await page.goto("http://localhost:9080");

  await page.waitForURL("http://localhost:5556/dex/auth**");

  const url = page.url();
  console.log(`Redirected to: ${url}`);

  await page.locator(':text("Log in with Email")').click();

  await page.locator("#login").fill("admin@example.com");
  await page.locator("#password").fill("password");

  await page.locator('button:text("Login")').click();

  const url2 = page.url();
  console.log(`Redirected to: ${url2}`);

  await page.waitForURL("http://localhost:9080");
});
