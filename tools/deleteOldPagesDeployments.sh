#!/bin/bash

accountId="$CF_ACCOUNT_ID"
apiKey="$CF_API_KEY"
projectName="traefik-oidc-auth"

if [ -z "$accountId" ]; then
  echo "Please specify your Cloudflare Account Id by running: export CF_ACCOUNT_ID=xxx"
  exit -1
fi
if [ -z "$apiKey" ]; then
  echo "Please specify your Cloudflare API Key by running: export CF_API_KEY=xxx"
  exit -1
fi

jsonData=$(curl -sS --request GET \
	--url https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}/deployments \
	--header "Content-Type: application/json" \
	--header "Authorization: Bearer ${apiKey}")

for i in $(seq 0 $(($(jq '.result | length' <<< "$jsonData") - 1))); do
  # Extract each property from the JSON
  id=$(jq -r ".result[$i].id" <<< "$jsonData")
  environment=$(jq -r ".result[$i].environment" <<< "$jsonData")
  aliasCount=$(jq -r ".result[$i].aliases | length" <<< "$jsonData")
  branchName=$(jq -r ".result[$i].deployment_trigger.metadata.branch" <<< "$jsonData")
  
  #if [[ "$environment" == "preview" && ( "$branchName" =~ ^backport/.*$ || "$branchName" =~ ^feature/.*$ || $aliasCount == 0 ) ]];
  if [ $aliasCount == 0 ]
  then
  	echo ""
  	echo "Id: $id"
  	echo "Environment: $environment"
	echo "Branch: ${branchName}"
	echo "Alias Count: ${aliasCount}"

	read -p "Press enter to delete... " -n1 -s

	curl --request DELETE \
		--url https://api.cloudflare.com/client/v4/accounts/${accountId}/pages/projects/${projectName}/deployments/${id}?force=true \
		--header "Content-Type: application/json" \
		--header "Authorization: Bearer ${apiKey}"
  fi
done
