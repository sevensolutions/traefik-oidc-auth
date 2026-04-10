# E2E Tests

End to end tests are executed by using [*Microsoft Playwright*](https://playwright.dev/).
The test infrastructure is set up by [*docker compose*](https://docs.docker.com/compose/).

Test files are located in the *./tests*-folder within subfolders for different configurations or IDPs.

We're using *bun* which can be installed by following the [official instructions](https://bun.com/docs/installation).

## First-time setup
```
bun install
bunx playwright install
```

## How to run the tests
```
bunx playwright test
```

You can also run the tests and watch the browser, or use the interactive UI mode:

```
bunx playwright test --headed
```
```
bunx playwright test --ui
```

## How to update keycloak master-realm.json

Run the docker compose stack and make changes to keycloak. Then run:

```
docker compose exec -it keycloak /opt/keycloak/bin/kc.sh export --file /opt/keycloak/data/import/master-realm.json --realm master
```
