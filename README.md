[![Build Status](https://travis-ci.org/MaritimeConnectivityPlatform/IdentityRegistry.svg?branch=master)](https://travis-ci.org/MaritimeConnectivityPlatform/IdentityRegistry)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FMaritimeConnectivityPlatform%2FIdentityRegistry.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FMaritimeConnectivityPlatform%2FIdentityRegistry?ref=badge_shield)

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
        proxy_set_header X-Client-Certificate $ssl_client_cert;
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
To support login with Openid Connect a [Keycloak](http://keycloak.jboss.org/) instance is needed. Keycloaks [Spring Security Adapter](https://keycloak.gitbooks.io/documentation/securing_apps/topics/oidc/java/spring-security-adapter.html) is used for easy integration. Get a instance up and running by following the [Keycloak manual](https://keycloak.gitbooks.io/documentation/server_installation/index.html), and don't forget to add the special [Maritime Cloud SPI modules](https://github.com/MaritimeCloud/MaritimeCloudKeycloakSpi). Now it is needed to create a few realms in keycloak. Do this by importing the files `setup/maritimecloud-realm.json`, `setup/projecttestusers-realm.json` and `setup/certificates-realm.json`.

You have now created the main "MaritimeCloud" realm, the "ProjectTestUsers" realm that is used to host users for organizations that do not have their own Identity Provider and the "Certificates" realm which is used for converting certificate authentication to OpenId Connect authentication. The "MaritimeCloud" realm comes with an administrative user for the Organization "Maritime Cloud", who has administrative rights for the entire Identity Registry API. This users should be used for setting up the Identity Registry. The users credentials are mc-admin@maritimecloud.net / admin. Normally users are not placed in the MaritimeCloud realm, but in the ProjectTestUsers realm or other dedicated Identity Providers, but for bootstraping purposes the user is placed in the MaritimeCloud realm. **This user should be deleted when going live.**

The "MaritimeCloud" realm uses a special JavaScript [authenticator](https://keycloak.gitbooks.io/documentation/server_admin/topics/authentication/flows.html) that bypasses Keycloaks normal merging of users that has the same email address. The "Certificates" realm uses a special Certificate authenticator (which is part of the Maritime Cloud SPI modules](https://github.com/MaritimeCloud/MaritimeCloudKeycloakSpi), and not related to Keycloaks builtin Certificate authenticator).

The MaritimeCloud and ProjectTestUsers realm includes each an adminstrative user that the API users to create users, clients and identity providers in Keycloak when needed. These are setup in `src/main/resources/application.yaml`, so make sure to keep the settings in there in sync with your setup! **Create new admim users or change their credentials when going live!**

The MaritimeCloud realm also contains a client called "setupclient" used in the bootstrap process mentioned below.

If setting up keycloak in a clustered environment remember to hmac-keystore provider for the realms you have created.

## Available REST API
The API is documented using Swagger/OpenAPI 2.0, and can be obtained from http://localhost:8443/v2/api-docs.

## Insert data
Inserting data can be done using the MaritimeCloud Management Portal, or by "firing" REST requests from the console. Below is a step by step guide to put data into the Identity Registry by firing REST requests from the console, commands for both Linux/Mac (using curl) and Windows (using Invoke-RestMethod in PowerShell).
On Windows in PowerShell you must first run the command below to disable certificate check for the PowerShell session:
```ps1
> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

First we apply fron an Organization to be added, in this case an organization called "Danish Maritime Authority". It is done by POST'ing prepared data in `setup/dma.json` to the REST interface:
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
    "mrn": "urn:mrn:mcl:org:dma",
    "url": "http://www.soefartsstyrelsen.dk/",
    "updatedAt": 1478089051176,
    "createdAt": 1478089051176
}
```

Make a note of the "mrn" which is used for identifing the Organization. In our running instance of FakeSMTP you will notice that 2 emails has been sent, one to the email of the organization and one the Maritime Cloud administrator defined in `src/main/resources/application.yaml`.

The next step is to approve the organization, which we will do using the administrative user mentioned above. First we must login as the adminstrative user. We here assume that the keycloak instance is available at `http://localhost:8080`.
```sh
$ RESULT=`curl --data "grant_type=password&client_id=setupclient&username=mc-admin@maritimecloud.net&password=admin" http://localhost:8080/auth/realms/MaritimeCloud/protocol/openid-connect/token`
$ TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`
```

```ps1
> $result=(Invoke-RestMethod -Uri http://localhost:8080/auth/realms/MaritimeCloud/protocol/openid-connect/token -Body "grant_type=password&client_id=setupclient&username=mc-admin@maritimecloud.net&password=admin" -Method Post)
> $token=(echo $result |  %{$_ -replace ".*access_token"":""", ""} |  %{$_ -replace """.*", ""})
```

A authentication token will be saved into the token variable, and can now be used to access the API. The token is only valid for a limited time and the we must then login again.

So now we want to approve the application to create the "Danish Maritime Authority" as an Organization. This is done as shown below. Notice that the MRN of the organization is used in the URL:
```sh
$ curl -k -H "Authorization: Bearer $TOKEN" https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/approve
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/approve -Headers @{"Authorization" = "Bearer $token"} -Method Get
```

Next we must define the roles that will grant the Organizations users rights, defined in `setup/dma-role.json`. This will grant users with "MCADMIN" in the `permissions` attribute administrative rights for the DMA organization:
```sh
$ curl -k -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data @setup/dma-role.json https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/role
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/role -ContentType "application/json" -Headers @{"Authorization" = "Bearer $token"} -InFile setup\dma-role.json -Method Post
```

And last but not least, we can then create a users for DMA with administrative rights. The user is defined in `setup/dma-user.json`:
```sh
$ curl -k -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data @setup/dma-user.json https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/user
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/user -ContentType "application/json" -Headers @{"Authorization" = "Bearer $token"} -InFile setup\dma-user.json -Method Post
```

Looking at FakeSMTP an email will has been sent to the email-address of the user with a temporary password that the user much change at first login. The user has been created in the "ProjectTestUsers" realm, since DMA has not set up a dedicated Identity Provider. To actually use the login you will need a web based client connected to keycloak. The Maritime Cloud Management Portal is a good example, and it can be run locally.

We can also issue a certificate for the user which can then be used for authentication:
```sh
$ curl -k -H "Authorization: Bearer $TOKEN" https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:dma-employee/certificate/issue-new
```

```ps1
> Invoke-RestMethod -Uri https://localhost/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:dma-employee/certificate/issue-new -Headers @{"Authorization" = "Bearer $token"} -Method Get
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

The certificate can now be used to authenticate the user. For example we can use it to create a vessel as shown below. Notice that we use https://localhost/x509/api/... instead of https://localhost/oidc/api/... when relying on certificate authentication.

```sh
$ curl -k -H "Content-Type: application/json" --key private.pem --cert certificate.pem --data @setup/ship1.json https://localhost/x509/api/org/urn:mrn:mcl:org:dma/vessel
```
In PowerShell using certificates is a bit tricky since it must be converted from the PEM format. In this case we will use [openssl](https://www.openssl.org/), and then use the converted certificate to create the vessel:
```ps1
> openssl pkcs12 -export -out user-cert.pfx -inkey private.pem -in certificate.pem
> Invoke-RestMethod -Uri https://localhost/x509/api/org/urn:mrn:mcl:org:dma/vessel -ContentType "application/json" -Certificate {Get-PfxCertificate -FilePath user-cert.pfx} -InFile setup\ship1.json -Method Post
```

The command will (mostly) return an echo of the json posted to the api:
```json
{
    "name": "POUL L\u00d8WEN\u00d8RN",
    "mrn": "urn:mrn:mcl:vessel:dma:poul-loewnoern",
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

## Building javadocs and UML diagrams
It is possible to build javadocs and UML diagrams for the project by running the command below. Note that it might require some non-java/maven dependencies. 
```sh
mvn javadoc:javadoc
```
The apidocs and UML diagrams are placed in `target/site/apidocs/`.

Some key UML diagrams has been manually placed in the `uml` folder for easy access. Remember to update those if you update the data model.


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FMaritimeConnectivityPlatform%2FIdentityRegistry.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FMaritimeConnectivityPlatform%2FIdentityRegistry?ref=badge_large)