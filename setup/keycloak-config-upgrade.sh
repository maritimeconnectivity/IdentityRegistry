#!/bin/bash

echo "This script requires that you have the Keycloak Admin CLI and jq installed."
echo "Information about how to install the Keycloak Admin CLI can be found at https://www.keycloak.org/docs/latest/server_admin/#the-admin-cli."
echo "If you are running a Linux based OS jq can be installed using the package manager of the OS."
echo ""

if ! hash jq 2>/dev/null
then
    echo "jq could not be found. Please install it before running this script."
    exit 1
fi

echo "Please input the path to the Keycloak Admin CLI script or press Enter if you have already added it to your PATH:"
read -r KCADM

if [ -z "$KCADM" ]
then
    KCADM=$(which kcadm.sh)
fi

which $KCADM > /dev/null
if [ $? -ne 0 ]
then
    echo "The Keycloak Admin CLI could not be found."
    exit 1
fi

echo "Please input the URL for the /auth endpoint of Keycloak:"
read -r URL

if [ -z "$URL" ]
then
    echo "URL was not set."
    exit 1
fi

echo "Please input the admin username for Keycloak:"
read -r ADMIN_USER

if [ -z "$ADMIN_USER" ]
then
    echo "Admin username was not set."
    exit 1
fi

echo "Please input the name of your Broker realm or press Enter for the default: [MCP]"
read -r BROKER_REALM

if [ -z "$BROKER_REALM" ]
then
    BROKER_REALM="MCP"
fi

echo "Please input the name of your Users realm or press Enter for the default: [Users]"
read -r USERS_REALM

if [ -z "$USERS_REALM" ]
then
    USERS_REALM="Users"
fi

echo "Please input the name of the client for the Broker realm in the $USERS_REALM realm or press Enter for the default: [mcp-broker]"
read -r USERS_BROKER_CLIENT

if [ -z "$USERS_BROKER_CLIENT" ]
then
    USERS_BROKER_CLIENT="mcp-broker"
fi

echo "Please input the name of your Certificates realm or press Enter for the default: [Certificates]"
read -r CERTIFICATES_REALM

if [ -z "$CERTIFICATES_REALM" ]
then
    CERTIFICATES_REALM="Certificates"
fi

echo "Please input the name of the client for the Broker realm in the $CERTIFICATES_REALM realm or press Enter for the default: [mcp-broker]"
read -r CERTIFICATES_BROKER_CLIENT

if [ -z "$CERTIFICATES_BROKER_CLIENT" ]
then
    CERTIFICATES_BROKER_CLIENT="mcp-broker"
fi

$KCADM config credentials --server "$URL" --realm master --user "$ADMIN_USER"

ATTRIBUTES=("uid" "flagstate" "callsign" "imo_number" "mmsi" "ais_type" "registered_port" "ship_mrn" "mrn" "permissions" "subsidiary_mrn" "mms_url" "url")

CLIENT_TEMPLATE=$($KCADM get client-scopes -r "$BROKER_REALM" | jq -r '.[] | select(.name == "mcp-client-template")')
CLIENT_TEMPLATE_ID=$(echo "$CLIENT_TEMPLATE" | jq -r '.id')
CLIENT_TEMPLATE_MAPPERS=$(echo "$CLIENT_TEMPLATE" | jq -r '.protocolMappers')
echo "$CLIENT_TEMPLATE_MAPPERS" > /tmp/kc_upgrade.tmp

MAPPER_TEMPLATE='{ "name": "%s", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": {"access.token.claim": true, "aggregate.attrs": "", "claim.name": "%s", "id.token.claim": true, "jsonType.label": "String", "multivalued": "", "user.attribute": "%s", "userinfo.token.claim": true} }'

echo "Creating default client mappers in Broker realm"
echo "==============================================="
for attr in "${ATTRIBUTES[@]}"; do
    export NAME="$attr mapper"
    MAPPER=$(jq -r '.[] | select(.name == env.NAME)' /tmp/kc_upgrade.tmp)
    if [ -z "$MAPPER" ]
    then
        echo "$NAME does not exist, will create it now."
        printf -v JSON "$MAPPER_TEMPLATE" "$NAME" "$attr" "$attr"
        $KCADM create client-scopes/"$CLIENT_TEMPLATE_ID"/protocol-mappers/models -r "$BROKER_REALM" -b "$JSON"
    else
        echo "$NAME already exists, will update it if needed."
        MAPPER_ID=$(echo "$MAPPER" | jq -r '.id')
        MAPPER_NEW=$(echo "$MAPPER" | jq -r '.config["id.token.claim"] = true | .config["userinfo.token.claim"] = true | .config["access.token.claim"] = true')
        $KCADM update client-scopes/"$CLIENT_TEMPLATE_ID"/protocol-mappers/models/"$MAPPER_ID" -r "$BROKER_REALM" -b "$MAPPER_NEW"
    fi
done
echo ""

MAPPER_TEMPLATE='{"identityProviderAlias":"%s","config":{"syncMode":"LEGACY","claim":"%s","user.attribute":"%s"},"name":"%s","identityProviderMapper":"oidc-user-attribute-idp-mapper"}'
for idp in "$USERS_REALM" "$CERTIFICATES_REALM"; do
    echo "Creating token mappers for $idp realm ID provider in $BROKER_REALM realm"
    echo "========================================================================"
    ID_PROVIDER_MAPPERS=$($KCADM get identity-provider/instances/$idp/mappers -r "$BROKER_REALM")
    if [ -z "$ID_PROVIDER_MAPPERS" ]
    then
        echo "Trying again with lowercase name"
        idp=$(echo "$idp" | tr '[:upper:]' '[:lower:]')
        ID_PROVIDER_MAPPERS=$($KCADM get identity-provider/instances/"$idp"/mappers -r "$BROKER_REALM")
    fi
    echo "$ID_PROVIDER_MAPPERS" > /tmp/kc_upgrade.tmp
    for attr in "${ATTRIBUTES[@]}"; do
        export NAME="$attr mapper"
        MAPPER=$(jq -r '.[] | select(.name == env.NAME)' /tmp/kc_upgrade.tmp)
        if [ -z "$MAPPER" ]
        then
            echo "$NAME does not exist, will create it now."
            printf -v JSON "$MAPPER_TEMPLATE" "$idp" "$attr" "$attr" "$NAME"
            $KCADM create identity-provider/instances/"$idp"/mappers -r "$BROKER_REALM" -b "$JSON"
        else
            echo "$NAME already exists."
        fi
    done
    echo ""
done

export USERS_BROKER_CLIENT
BROKER_CLIENT=$($KCADM get clients -r "$USERS_REALM" | jq -r '.[] | select(.clientId == env.USERS_BROKER_CLIENT)')
BROKER_CLIENT_ID=$(echo "$BROKER_CLIENT" | jq -r '.id')
BROKER_CLIENT_MAPPERS=$(echo "$BROKER_CLIENT" | jq -r '.protocolMappers')
echo "$BROKER_CLIENT_MAPPERS" > /tmp/kc_upgrade.tmp

MAPPER_TEMPLATE='{"protocol":"openid-connect","config":{"id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","multivalued":"","aggregate.attrs":"","user.attribute":"%s","claim.name":"%s","jsonType.label":"String"},"name":"%s","protocolMapper":"oidc-usermodel-attribute-mapper"}'

echo "Creating client mappers for Broker realm in the $USERS_REALM realm"
echo "=================================================================="
for attr in "${ATTRIBUTES[@]}"; do
    export NAME="$attr mapper"
    MAPPER=$(jq -r '.[] | select(.name == env.NAME)' /tmp/kc_upgrade.tmp)
    if [ -z "$MAPPER" ]
    then
        echo "$NAME does not exists, will create it now."
        printf -v JSON "$MAPPER_TEMPLATE" "$attr" "$attr" "$NAME"
        $KCADM create clients/"$BROKER_CLIENT_ID"/protocol-mappers/models -r "$USERS_REALM" -b "$JSON"
    else 
        echo "$NAME already exists."
    fi
done
echo ""

export CERTIFICATES_BROKER_CLIENT
BROKER_CLIENT=$($KCADM get clients -r "$CERTIFICATES_REALM" | jq -r '.[] | select(.clientId == env.CERTIFICATES_BROKER_CLIENT)')
BROKER_CLIENT_ID=$(echo "$BROKER_CLIENT" | jq -r '.id')
BROKER_CLIENT_MAPPERS=$(echo "$BROKER_CLIENT" | jq -r '.protocolMappers')
echo "$BROKER_CLIENT_MAPPERS" > /tmp/kc_upgrade.tmp

MAPPER_TEMPLATE='{"protocol":"openid-connect","config":{"id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","multivalued":"","aggregate.attrs":"","user.attribute":"%s","claim.name":"%s","jsonType.label":"String"},"name":"%s","protocolMapper":"oidc-usermodel-attribute-mapper"}'

echo "Creating client mappers for Broker realm in the $CERTIFICATES_REALM realm"
echo "=================================================================="
for attr in "${ATTRIBUTES[@]}"; do
    export NAME="$attr mapper"
    MAPPER=$(jq -r '.[] | select(.name == env.NAME)' /tmp/kc_upgrade.tmp)
    if [ -z "$MAPPER" ]
    then
        echo "$NAME does not exists, will create it now."
        printf -v JSON "$MAPPER_TEMPLATE" "$attr" "$attr" "$NAME"
        $KCADM create clients/"$BROKER_CLIENT_ID"/protocol-mappers/models -r "$CERTIFICATES_REALM" -b "$JSON"
    else 
        echo "$NAME already exists."
    fi
done
echo ""

rm /tmp/kc_upgrade.tmp
exit 0
