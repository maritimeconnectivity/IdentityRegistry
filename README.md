# Maritime Cloud Identity Registry
This is the implementation of the Maritime Cloud Identity Registry. It is currently under active development changes that are not backward compatible should be expected. It is under the Apache 2.0 License.

## Setup Database
A MySQL/MariaDB is used as datastore, it can be setup running this commands from the console:
```sh
$ ./setup/setup-db.sh
```
You will be prompted for the root password for the database. The script will create a new user and this user will be used to create the needed tables.
If you see this error: ```ERROR 1698 (28000): Access denied for user 'root'@'localhost'```, try running the command with ```sudo```.

The database can be drop with this command:
```sh
$ ./setup/drop-db.sh
```

## Build
Build using you favorite IDE or using the console:
```sh
$ mvn clean install
```

## Run
Run using you favorite IDE or using the console:
```sh
$ java -jar target/mc-identityregistry-core-latest.war
```
Change the version number as needed.

## Authentication using Openid Connect (Required!) 
To support login with Openid Connect a [Keycloak](http://keycloak.jboss.org/) instance is needed. Keycloaks [Spring Security Adapter](https://keycloak.gitbooks.io/securing-client-applications-guide/content/v/latest/topics/oidc/java/spring-security-adapter.html) is used for easy integration. Get a instance up and running by following the [Keycloak manual](https://keycloak.gitbooks.io/server-installation-and-configuration/content/v/latest/index.html). Then create a new realm by importing the file `setup/maritimecloud-realm.json`. Make sure it is called "MaritimeCloud". If you want to use REST commands to input data into the Identity Registry create a client using `setup/setupclient.json`. In the various configuration files included with the source it is assumed that keycloak runs on port 9080 by using the option `-Djboss.socket.binding.port-offset=1000`. If this is not the case in your setup the configuration files must be adjusted accordingly.

If you want to setup a realm yourself, follow the guide below, but if you have imported the realm as described above you can just skip this part.

See Keycloaks documentation for how to register a client. After setting it up get the "Keycloak JSON" from the clients installation tab and place it in `src/main/webapp/WEB-INF/keycloak.json`.

Now a special user must be set up to allow the registration of Identity Providers in keycloak. Create the user in Keycloak, assign a non-temporary password and assign the "admin" role. Now put the info of the created user in `src/main/resources/application.yaml` like this:
```yaml
net:
    maritimecloud:
        idreg:
            keycloak-broker-admin-user: idreg-admin
            keycloak-broker-admin-password: idreg-admin
            keycloak-broker-admin-client: security-admin-console
            keycloak-broker-realm: MaritimeCloud
            keycloak-broker-base-url: http://localhost:9080/auth/
```
The client `security-admin-console` is a standard Keycloak client that will be used when accessing the Keycloak API, but its settings needs to be changed first. So go to the configuration page of the client `security-admin-console` and enable "Direct Access Grants", which will allow the create user to login and access the keycloak API.

Besides the Identity Providers we also need to be able to create users in Keycloak, to support OpenID Connect login of admin users, and users from an Organization without their own Identity Provider. This can be the same keycloak instance as used for Identity Providers, or a different one, or perhaps the same instance but a different realm. In this other instance/realm a user must be created in the same way as described above, and the info saved to `src/main/resources/application.yaml`, like this:
```yaml
net:
    maritimecloud:
        idreg:
            keycloak-project-users-admin-user: idreg-admin
            keycloak-project-users-admin-password: idreg-admin
            keycloak-project-users-admin-client: security-admin-console
            keycloak-project-users-realm: MaritimeCloud
            keycloak-project-users-base-url: http://localhost:9080/auth/
```

To setup an organization with its own Identity Provider, the Identity Registry can automatically set it up using a few extra attributes in the organization json when creating it. See ```setup/testidp.json``` for an example. The Identity Provider must support OpenID Connect and have set up a client. The client id and secret is 2 of the needed attributes for Identity Provider registration, the last one is a link to the "well-known url", as defined in the [OpenID Connect Discovery Specs](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

## Authentication using certificates
To login using certificates a client certificate must first be generated and signed by the MaritimeCloud Identity Registry. For a vessel it can be done like this:
```sh
$ curl -b cookies.txt -k https://localhost:8443/oidc/api/org/DMA/vessel/1/generatecertificate
```

This will return a public key, private key and a certificate in PEM format for this vessel signed by the MaritimeCloud, and should be saved locally. The certificate is saved in the Identity Registry, but the keys is not.

If the private key is stored in ```ship-private.pem``` and the certificate in ```ship-cert.pem```, an example of use could be this:
```sh
$ curl -i -k https://localhost:8443/x509/api/org/DMA/vessel/2 --key ship-private.pem --cert ship-cert.pem
```

## Available REST API
The API is documented using Swagger/OpenAPI 2.0, and can be obtained from [http://<hostname:port>/v2/api-docs].

## Insert data
Inserting data can be done using the MaritimeCloud Portal, or by "firing" REST requests from the console. Below is a step by step guide to put data into the Identity Registry using by firing REST requests from the console, commands for both Linux/Mac (using curl) and Windows (using Invoke-RestMethod in PowerShell).
On Windows in PowerShell you must first run the command below to disable certificate check for the PowerShell session:
```ps1
> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

First an Organization must be added. It can be done like this using curl from the console to POST data to the REST interface:
```sh
$ curl -k -H "Content-Type: application/json" --data @setup/dma.json https://localhost:8443/oidc/api/org/apply
```

```ps1
> Invoke-RestMethod -Uri https://localhost:8443/oidc/api/org/apply -ContentType "application/json" -InFile setup\dma.json -Method Post
```

This will return some json looking like this, which is mostly an echo of the posted json:
```json
{"createdAt":1448544528797,"updatedAt":1448544528797,"name":"Danish Maritime Authority","shortName":"DMA","url":"http://www.soefartsstyrelsen.dk/","country":"Denmark","password":"iklugohe4agngesqpv3c4jm34g"}
```

So now an Organization named "Danish Maritime Authority" has been created. Make a note of the "shortName" and "password" since they will be used for authentication against Keycloak, which is the next step. We here assume that the keycloak instance is available at
```sh
$ RESULT=`curl --data "grant_type=password&client_id=setupclient&username=dma&password=iklugohe4agngesqpv3c4jm34g" http://localhost:9080/auth/realms/MaritimeCloud/protocol/openid-connect/token`
$ TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`
```

```ps1
>$result=(Invoke-RestMethod -Uri http://localhost:9080/auth/realms/MaritimeCloud/protocol/openid-connect/token -Body "grant_type=password&client_id=setupclient&username=dma&password=iklugohe4agngesqpv3c4jm34g" -Method Post)
>$token=(echo $result |  %{$_ -replace ".*access_token"":""", ""} |  %{$_ -replace """.*", ""})
```

Change the username and password as needed. A authentication token will be saved into the token variable, and can now be used to access the API.

To create some vessels for Organization with shortname "DMA", do this (note that "DMA" is included in the url):
```sh
$ curl -k -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data @setup/ship1.json https://localhost:8443/oidc/api/org/DMA/vessel
$ curl -k -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data @setup/ship2.json https://localhost:8443/oidc/api/org/DMA/vessel
```

```ps1
> Invoke-RestMethod -Uri https://localhost:8443/oidc/api/org/DMA/vessel -ContentType "application/json" -Headers @{"Authorization" = "Bearer $token"} -InFile setup\ship1.json -Method Post
> Invoke-RestMethod -Uri https://localhost:8443/oidc/api/org/DMA/vessel -ContentType "application/json" -Headers @{"Authorization" = "Bearer $token"} -InFile setup\ship2.json -Method Post
```

Each command will (mostly) return an echo of the json posted to the api:
```json
{"id":1,"createdAt":1448545611826,"updatedAt":1448545611826,"vesselOrgId":"dma1","name":"POUL LØWENØRN","attributes":[{"id":1,"createdAt":1448545611838,"updatedAt":1448545611838,"attributeName":"imo-number","attributeValue":"9250969"},{"id":2,"createdAt":1448545611840,"updatedAt":1448545611840,"attributeName":"callsign","attributeValue":"OZZX"},{"id":3,"createdAt":1448545611844,"updatedAt":1448545611844,"attributeName":"port-of-register","attributeValue":"KØBENHAVN"}],"certificates":[]}
```
