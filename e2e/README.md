# E2E Tests

End to end tests are executed by using [*Microsoft Playwright*](https://playwright.dev/).
The test infrastructure is set up by [*docker compose*](https://docs.docker.com/compose/).

Test files are located in the *./tests*-folder within subfolders for different configurations or IDPs.

## First-time setup
```
npm install
npx playwright install
```

## How to run the tests
```
npx playwright test
```

You can also run the tests and watch the browser, or use the interactive UI mode:

```
npx playwright test --headed
```
```
npx playwright test --ui
```

## How to update keycloak master-realm.json

Run the docker compose stack and make changes to keycloak. Then run:

```
docker compose exec -it keycloak /opt/keycloak/bin/kc.sh export --file /opt/keycloak/data/import/master-realm.json --realm master
```
