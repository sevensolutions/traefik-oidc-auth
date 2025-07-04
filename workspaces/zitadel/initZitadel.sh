#!/bin/sh

URL="${ZITADEL_URL:-http://127-0-0-1.sslip.io:8000}"
PAT=$(<./machinekey/admin-pat.txt)

# -----------------------------------------------------------------------------
# Get Org Id
# -----------------------------------------------------------------------------

meResponse=$(curl -s -X GET -L "${URL}/management/v1/orgs/me" \
  -H "Authorization: Bearer ${PAT}")

orgId=$(echo $meResponse | jq -r '.org.id')

echo "Org Id: ${orgId}"

# -----------------------------------------------------------------------------
# Setup Project
# -----------------------------------------------------------------------------

projectsResponse=$(curl -s -X POST -L "${URL}/management/v1/projects/_search" \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
-H "Authorization: Bearer ${PAT}" \
-d '{
  "query": {
    "offset": "0",
    "limit": 1,
    "asc": true
  },
  "queries": [
    {
      "nameQuery": {
        "name": "Traefik",
        "method": "TEXT_QUERY_METHOD_EQUALS"
      }
    }
  ]
}')

projectId=$(echo $projectsResponse | jq -r '.result[0].id')

if [ "$projectId" == "null" ]; then
  createProjectResponse=$(curl -s -X POST -L "${URL}/management/v1/projects" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer ${PAT}" \
    -d '{
    "name": "Traefik",
    "projectRoleAssertion": false,
    "projectRoleCheck": false,
    "hasProjectCheck": false,
    "privateLabelingSetting": "PRIVATE_LABELING_SETTING_UNSPECIFIED"
    }')

  projectId=$(echo $createProjectResponse | jq -r '.id')

  echo "Created new project"
fi

echo "Using Project with Id: ${projectId}"

# -----------------------------------------------------------------------------
# Setup Application
# -----------------------------------------------------------------------------

appsResponse=$(curl -s -X POST -L "${URL}/management/v1/projects/${projectId}/apps/_search" \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
-H "Authorization: Bearer ${PAT}" \
-d '{
  "query": {
    "offset": "0",
    "limit": 1,
    "asc": true
  },
  "queries": [
    {
      "nameQuery": {
        "name": "traefik",
        "method": "TEXT_QUERY_METHOD_EQUALS"
      }
    }
  ]
}')

appId=$(echo $appsResponse | jq -r '.result[0].id')

if [ "$appId" == "null" ]; then
  createAppResponse=$(curl -s -X POST -L "${URL}/management/v1/projects/${projectId}/apps/oidc" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer ${PAT}" \
    -d '{
    "name": "traefik",
    "redirectUris": [
        "http://localhost:9080/oidc/callback",
        "https://localhost:9080/oidc/callback"
    ],
    "postLogoutRedirectUris": [
        "http://localhost:9080/oidc/callback",
        "https://localhost:9080/oidc/callback"
    ],
    "responseTypes": [
        "OIDC_RESPONSE_TYPE_CODE"
    ],
    "grantTypes": [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN"
    ],
    "appType": "OIDC_APP_TYPE_WEB",
    "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
    "version": "OIDC_VERSION_1_0",
    "devMode": true,
    "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
    "accessTokenRoleAssertion": true,
    "idTokenRoleAssertion": true,
    "idTokenUserinfoAssertion": true,
    "clockSkew": "1s"
    }')

  echo $createAppResponse

  appId=$(echo $createAppResponse | jq -r '.appId')

  echo "Created new app"
fi

echo "Using App with Id: ${appId}"

# -----------------------------------------------------------------------------
# Setup Users
# -----------------------------------------------------------------------------

function ensureUser() {
  username=$1
  firstName=$2
  lastName=$3

  usersResponse=$(curl -s -X POST -L "${URL}/management/v1/users/_search" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer ${PAT}" \
    --data-raw '{
      "query": {
        "offset": "0",
        "limit": 1,
        "asc": true
      },
      "sortingColumn": "USER_FIELD_NAME_UNSPECIFIED",
      "queries": [
        {
          "userNameQuery": {
            "userName": "'"${username}"'",
            "method": "TEXT_QUERY_METHOD_EQUALS"
          }
        }
      ]
    }')

  userId=$(echo $usersResponse | jq -r '.result[0].id')

  if [ "$userId" == "null" ]; then
    createUserResponse=$(curl -s -X POST -L "${URL}/management/v1/users/human/_import" \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json' \
      -H "Authorization: Bearer ${PAT}" \
      -d '{
        "userName": "'"${username}"'",
        "profile": {
          "firstName": "'"${firstName}"'",
          "lastName": "'"${lastName}"'",
          "nickName": "'"${username}"'",
          "displayName": "'"${username}"'",
          "preferredLanguage": "en",
          "gender": "GENDER_UNSPECIFIED"
        },
        "email": {
          "email": "'"${username}"'@example.com",
          "isEmailVerified": true
        },
        "password": "Password1!",
        "passwordChangeRequired": false
      }')

      echo "Created user: ${username}"
  fi
}

ensureUser "bob" "Bob" "Newman"
ensureUser "alice" "Alice" "Newman"
