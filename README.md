[![Java CI with Maven](https://github.com/maritimeconnectivity/IdentityRegistry/actions/workflows/maven.yml/badge.svg)](https://github.com/maritimeconnectivity/IdentityRegistry/actions/workflows/maven.yml)

# Maritime Connectivity Platform Identity Registry
This is the implementation of the MCP Identity Registry. It is under the Apache 2.0 License.

The Maritime Connectivity Platform was formerly known as the Maritime Cloud and therefore there might still be references to that in this project.  

A detailed guide on how to setup the Identity Registry that should be used in conjunction with this README can be found in the document [MIR Setup](./setup/guide/MIR_setup.pdf). 

## Setup Database
A MySQL/MariaDB is used as datastore, it can be setup running this commands from the console:
```sh
$ ./setup/setup-db.sh
```
You will be prompted for the root password for the database. The script will create a new user and this user will be used to create the needed tables.
If you see this error: ```ERROR 1698 (28000): Access denied for user 'root'@'localhost'```, try running the command with ```sudo```.

The database can be dropped with this command:
```sh
$ ./setup/drop-db.sh
```

## Build
* Requirement : OpenJDK 8

Build using you favorite IDE or using the console:
```sh
$ mvn clean install
```

## Run
Before starting the Identity Registry API there are a few requirements to setup.

First it is recommended to either run the application with a custom application.yaml or to change the value of spring.profile.active to development. 

It is recommended to have a SMTP server running since emails are send when creating new Organizations or Users. For testing [FakeSMTP](https://nilhcem.github.io/FakeSMTP/) is recommended. See `src/main/resources/application.yaml` for email configuration.

It is recommended to run the Identity Registry behind a dedicated http server, we recommend nginx, with a configuration similar to this:

```conf
server {
    listen 443 ssl;
    server_name _name_;
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_client_certificate /etc/ssl/mc-ca-chain.pem;
    ssl_verify_client optional;
    ssl_crl /etc/ssl/combined-crl.pem;
    ssl_verify_depth 2;
    location / {
        proxy_pass http://localhost:8443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Certificate $ssl_client_escaped_cert;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, Accept, X-Requested-With, remember-me, authorization';
    }
}
```

The `ssl_certificate` and `ssl_certificate_key` properties in the configuration above points to the standard self-signed certificate that comes with an Ubuntu Linux. The `ssl_client_certificate` and `ssl_crl` should point to the `mc-ca-chain.pem` and `combined-crl.pem` provided in the the root of this project.

Run using you favorite IDE or using the console:

```sh
$ java -jar target/mc-identityregistry-core-latest.war
```
Change the version number as needed. The Identity Registry will now be running and requests to https://localhost/api/... will be forwarded through nginx to the spring boot application on http://localhost:8443/api/... that wraps the API.

The first time the application is started it creates the database tables needed. You should now insert an organization used for bootstraping by running this script:

```sh
$ ./setup/create-mc-org.sh
```

## Authentication using Openid Connect (Required!) 
To support login with Openid Connect a [Keycloak](https://www.keycloak.org/) instance is needed. Keycloaks [Spring Security Adapter](https://www.keycloak.org/docs/latest/securing_apps/index.html#_spring_security_adapter) is used for easy integration. Get a instance up and running by following the [Keycloak manual](https://www.keycloak.org/docs/latest/server_installation/), and don't forget to add the special [MCP SPI modules](https://github.com/maritimeconnectivity/MCPKeycloakSpi). Now it is needed to create a few realms in keycloak. Do this by importing the files `setup/MCP-realm.json`, `setup/Users-realm.json` and `setup/Certificates-realm.json`.

You have now created the main "MCP" realm, the "Users" realm that is used to host users for organizations that do not have their own Identity Provider and the "Certificates" realm which is used for converting certificate authentication to OpenId Connect authentication. The "MCP" realm comes with an administrative user for the Organization "Bootstrap Org", which has administrative rights for the entire Identity Registry API. This user should be used for setting up the Identity Registry. The users credentials are mcp-admin@maritimeconnectivity.net / admin. Normally users are not placed in the MCP realm, but in the Users realm or other dedicated Identity Providers, but for bootstrapping purposes the user is placed in the MCP realm. **This user should be deleted when going live.**

The "MCP" realm uses a special JavaScript [authenticator](https://www.keycloak.org/docs/latest/server_admin/#_authentication-flows) that bypasses Keycloaks normal merging of users that has the same email address. The "Certificates" realm uses a special Certificate authenticator (which is part of the [MCP SPI modules](https://github.com/maritimeconnectivity/MCPKeycloakSpi), and not related to Keycloak's builtin Certificate authenticator).

The MCP and Users realm includes each an administrative user that the API users to create users, clients and identity providers in Keycloak when needed. These are setup in `src/main/resources/application.yaml`, so make sure to keep the settings in there in sync with your setup! **Create new admim users or change their credentials when going live!**

The MCP realm also contains a client called "setupclient" used in the bootstrap process mentioned below.

If setting up keycloak in a clustered environment remember to create a hmac-keystore provider for the realms you have created.

## Available REST API
The API is documented using Swagger/OpenAPI 2.0, and can be obtained from http://localhost:8443/v2/api-docs.

## Insert data
Inserting data can be done using the MCP Management Portal, or by "firing" REST requests from the console. Below is a step by step guide to put data into the Identity Registry by firing REST requests from the console, commands for both Linux/Mac (using curl) and Windows (using Invoke-RestMethod in PowerShell).
On Windows in PowerShell you must first run the command below to disable certificate check for the PowerShell session:
```ps1
> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

First we apply fro, an Organization to be added, in this case an organization called "Danish Maritime Authority". It is done by POST'ing prepared data in `setup/dma.json` to the REST interface:
```sh
$ curl -k -H "Content-Type: application/json" --data @setup/dma.json https://localhost/oidc/api/org/apply
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/apply -ContentType "application/json" -InFile setup\dma.json -Method Post
```

This will return some json looking like this, which is mostly an echo of the posted json:
```json
{
    "name": "Danish Maritime Authority",
    "address": "Carl Jacobsensvej 31, 2500 Valby",
    "country": "Denmark",
    "email": "dma@dma.dk",
    "mrn": "urn:mrn:mcp:org:idp1:dma",
    "url": "http://www.soefartsstyrelsen.dk/",
    "updatedAt": 1478089051176,
    "createdAt": 1478089051176
}
```

Make a note of the "mrn" which is used for identifying the Organization. In our running instance of FakeSMTP you will notice that 2 emails has been sent, one to the email of the organization and one the MCP administrator defined in `src/main/resources/application.yaml`.

The next step is to approve the organization, which we will do using the administrative user mentioned above. First we must login as the administrative user. We here assume that the keycloak instance is available at `http://localhost:8080`.
```sh
$ RESULT=`curl --data "grant_type=password&client_id=setupclient&username=mcp-admin@maritimeconnectivity.net&password=admin" http://localhost:8080/auth/realms/MCP/protocol/openid-connect/token`
$ TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`
```

```ps1
> $result=(Invoke-RestMethod -Uri http://localhost:8080/auth/realms/MCP/protocol/openid-connect/token -Body "grant_type=password&client_id=setupclient&username=mcp-admin@maritimeconnectivity.net&password=admin" -Method Post)
> $token=(echo $result |  %{$_ -replace ".*access_token"":""", ""} |  %{$_ -replace """.*", ""})
```

A authentication token will be saved into the token variable, and can now be used to access the API. The token is only valid for a limited time and then we must login again.

So now we want to approve the application to create the "Danish Maritime Authority" as an Organization. This is done as shown below. Notice that the MRN of the organization is used in the URL:
```sh
$ curl -k -H "Authorization: Bearer $TOKEN" https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/approve
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/approve -Headers @{"Authorization" = "Bearer $token"} -Method Get
```

Next we must define the roles that will grant the Organizations users rights, defined in `setup/dma-role.json`. This will grant users with "MCPADMIN" in the `permissions` attribute administrative rights for the DMA organization:
```sh
$ curl -k -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data @setup/dma-role.json https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/role
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/role -ContentType "application/json" -Headers @{"Authorization" = "Bearer $token"} -InFile setup\dma-role.json -Method Post
```

And last but not least, we can then create a user for DMA with administrative rights. The user is defined in `setup/dma-user.json`:
```sh
$ curl -k -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data @setup/dma-user.json https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user -ContentType "application/json" -Headers @{"Authorization" = "Bearer $token"} -InFile setup\dma-user.json -Method Post
```

Looking at FakeSMTP an email will has been sent to the email-address of the user with a temporary password that the user much change at first login. The user has been created in the "Users" realm, since DMA has not set up a dedicated Identity Provider. To actually use the login you will need a web based client connected to keycloak. The MCP Management Portal is a good example, and it can be run locally.

We can also issue a certificate for the user which can then be used for authentication:
```sh
$ curl -k -H "Authorization: Bearer $TOKEN" https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:dma-employee/certificate/issue-new
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:dma-employee/certificate/issue-new -Headers @{"Authorization" = "Bearer $token"} -Method Get
```
This will return a BASE64 encoded JKS keystore, a BASE64 encoded PKCS#12 keystore, a password for the keystores, a public key and private key and a certificate in PEM format embedded in JSON, looking something like this:
```json
{
    "jksKeystore": "/u3+7QAA...",
    "keystorePassword": "fg3543s...",
    "pemCertificate": {
          "certificate": "-----BEGIN CERTIFICATE-----\\nMIID4zCCA2igAwIBAgIBATAKBggqhkjOPQQ...",
          "privateKey": "-----BEGIN PRIVATE KEY-----\\nMIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGn...",
          "publicKey": "-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECysC+u..."
    },
    "pkcs12Keystore": "MIIGmAIB..."   
}
```
Note that this is the only time the private key is available, so make sure to save it. Save the output into separate files. Make sure to replace "\\\\n" with linebreaks!

The certificate can now be used to authenticate the user. For example, we can use it to create a vessel as shown below. Notice that we use https://localhost/x509/api/... instead of https://localhost/oidc/api/... when relying on certificate authentication.

```sh
$ curl -k -H "Content-Type: application/json" --key private.pem --cert certificate.pem --data @setup/ship1.json https://localhost/x509/api/org/urn:mrn:mcp:org:idp1:dma/vessel
```
In PowerShell using certificates is a bit tricky since it must be converted from the PEM format. In this case we will use [openssl](https://www.openssl.org/), and then use the converted certificate to create the vessel:
```ps1
> openssl pkcs12 -export -out user-cert.pfx -inkey private.pem -in certificate.pem
> Invoke-RestMethod -Uri https://localhost/x509/api/org/urn:mrn:mcp:org:idp1:dma/vessel -ContentType "application/json" -Certificate {Get-PfxCertificate -FilePath user-cert.pfx} -InFile setup\ship1.json -Method Post
```

The command will (mostly) return an echo of the json posted to the api:
```json
{
    "name": "POUL L\u00d8WEN\u00d8RN",
    "mrn": "urn:mrn:mcp:vessel:idp1:dma:poul-loewnoern",
    "attributes": [
        {
            "attributeName": "imo-number",
            "attributeValue": "9250969",
            "createdAt": 1478090837134,
            "updatedAt": 1478090837134
        },
        {
            "attributeName": "callsign",
            "attributeValue": "OZZX",
            "createdAt": 1478090837136,
            "updatedAt": 1478090837136
        },
        {
            "attributeName": "port-of-register",
            "attributeValue": "K\u00d8BENHAVN",
            "createdAt": 1478090837138,
            "updatedAt": 1478090837138
        }
    ],
    "createdAt": 1478090837128,
    "updatedAt": 1478090837128
}

```

## Certificate issuing by [Certificate Signing Request](https://en.wikipedia.org/wiki/Certificate_signing_request)
The MIR supports signing of PEM encoded PKCS#10 certificate signing requests. It is usually generated for the entity where the certificate will be stored/owned and contains the entity's information such as the organization name, common name (domain name), locality, and country, which will be overwritten by the corresponding information stored in MIR. A CSR also contains the public key that will be included in the certificate. A private key is usually created at the same time that you create the CSR, and expected to be stored and treated securely. The algorithm and bit-length pairs of CSR that MIR supports are *RSA:>=2048, DSA:>=2048, EC:>=224, and EdDSA:256*.

An example of how a CSR can be generated using an elliptic curve key pair using OpenSSL:
### Step 1: Generate private key
```sh
$ openssl ecparam -out private.key -name secp384r1 -genkey
```
This generates an ECC private key using the named curve **secp384r1**. 

### Step 2: Generate CSR
```sh
$ openssl req -new -key private.key -out request.csr
```
This will prompt you to fill in the attributes of the certificate. For this you can just use dummy data, as they in the end will be replaced with data from the MIR database. 

### Step 3: Send CSR to MIR for signing
```sh
$ curl -k -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/plain" --data-binary @request.csr https://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:dma-employee/certificate/issue-new/csr
```
This will send the CSR to the MIR to be signed for the user with the MRN urn:mrn:mcp:user:idp1:dma:dma-employee. The MIR will then return a certificate chain containing the signed certificate followed by the intermediate CA that signed it, looking like this:
```
-----BEGIN CERTIFICATE-----
....
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
....
-----END CERTIFICATE-----
```

## Building javadocs and UML diagrams
It is possible to build javadocs and UML diagrams for the project by running the command below. Note that it might require some non-java/maven dependencies. 
```sh
mvn javadoc:javadoc
```
The apidocs and UML diagrams are placed in `target/site/apidocs/`.

Some key UML diagrams has been manually placed in the `uml` folder for easy access. Remember to update those if you update the data model.
