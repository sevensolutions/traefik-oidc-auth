# E2E Tests

End to end tests are executed by using [*Microsoft Playwright*](https://playwright.dev/).
The test infrastructure is set up by [*docker compose*](https://docs.docker.com/compose/).

Test files are located in the *./tests*-folder within subfolders for different configurations or IDPs.

## How to run the tests

```
npm install
npx playwright test
```

You can also run the tests and watch the browser, or use the interactive UI mode:

```
npx playwright test --headed
```
```
npx playwright test --ui
```
