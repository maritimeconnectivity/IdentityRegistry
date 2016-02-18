# Maritime Cloud Identity Registry (test implementation)
This is a test implementation of the Maritime Cloud Identity Registry. It is expected to be changed and rewritten a number of times before being useful to anyone. It is under the Apache 2.0 License.

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
$ mvn install
```

## Run
Run using you favorite IDE or using the console:
```sh
$ java -jar target/mc-identityregistry-core-0.0.1-SNAPSHOT.war
```
Change the version number as needed.

## Available REST API
The API changes very rapidly at the moment, so look in the output when the app start for "RequestMappingHandlerMapping" messages that mentions the endpoints.  

## Insert data
First an Organization must be added. It can be done like this using curl from the console to POST data to the REST interface:
```sh
$ curl -k -H "Content-Type: application/json" --data @setup/dma.json https://localhost:8443/admin/api/org/apply
```

This will return some json looking like this, which is mostly an echo of the posted json:
```json
{"createdAt":1448544528797,"updatedAt":1448544528797,"name":"Danish Maritime Authority","shortName":"DMA","url":"http://www.soefartsstyrelsen.dk/","country":"Denmark","password":"iklugohe4agngesqpv3c4jm34g"}
```

So now an Organization named "Danish Maritime Authority" has been created. Make a note of the "shortName" and "password" since they will be used for authentication, which is the next step:
```sh
$ curl -k -i -X POST -d username=DMA -d password=iklugohe4agngesqpv3c4jm34g -c ./cookies.txt https://localhost:8443/login
```
Change the username and password as needed. A authentication token will be saved into the file cookies.txt, and can now be used to access the API.

To create some vessels for Organization with shortname "DMA", do this (note that "DMA" is included in the url):
```sh
$ curl -k -H "Content-Type: application/json" -b cookies.txt --data @setup/ship1.json https://localhost:8443/admin/api/org/DMA/vessel
$ curl -k -H "Content-Type: application/json" -b cookies.txt --data @setup/ship2.json https://localhost:8443/admin/api/org/DMA/vessel
```

Each command will (mostly) return an echo of the json posted to the api:
```json
{"id":1,"createdAt":1448545611826,"updatedAt":1448545611826,"vesselOrgId":"dma1","name":"POUL LØWENØRN","attributes":[{"id":1,"createdAt":1448545611838,"updatedAt":1448545611838,"attributeName":"IMO number","attributeValue":"9250969"},{"id":2,"createdAt":1448545611840,"updatedAt":1448545611840,"attributeName":"callsign","attributeValue":"OZZX"},{"id":3,"createdAt":1448545611844,"updatedAt":1448545611844,"attributeName":"Port Of Register","attributeValue":"KØBENHAVN"}],"certificates":[]}
```

## Login using Openid Connect (Keykloak)
To support login with Openid Connect a [Keycloak](http://keycloak.jboss.org/) instance is needed. Keycloaks [Spring Security Adapter](http://keycloak.github.io/docs/userguide/keycloak-server/html/ch08.html#spring-security-adapter) is used for easy integration. See Keycloaks documentation for how to register a client. After setting it up get the "Keycloak JSON" from the clients installation tab and place it in `src/main/webapp/WEB-INF/keycloak.json`.

Now a special user must be set up to allow the registration of Identity Providers in keycloak. Create the user in Keycloak, assign a non-temporary password and assign the "admin" role. Now put the info of the created user in `src/main/resources/application.properties` like this:
```properties
net.maritimecloud.idreg.keycloak-broker-admin-user=idreg-admin
net.maritimecloud.idreg.keycloak-broker-admin-password=idreg-admin
net.maritimecloud.idreg.keycloak-broker-admin-client=security-admin-console
net.maritimecloud.idreg.keycloak-broker-realm=master
net.maritimecloud.idreg.keycloak-broker-base-url=http://localhost:9080/auth/
```
The client `security-admin-console` is a standard Keycloak client that will be used when accessing the Keycloak API, but its settings needs to be changed first. So go to the configuration page of the client `security-admin-console` and enable "Direct Access Grants", which will allow the create user to login and access the keycloak API.

Besides the Identity Providers we also need to be able to create users in Keycloak, to support OpenID Connect login of admin users, and users from an Organization without their own Identity Provider. This can be the same keycloak instance as used for Identity Providers, or a different one, or perhaps the same instance but a different realm. In this other instance/realm a user must be created in the same way as described above, and the info saved to `src/main/resources/application.properties`, like this:
```properties
net.maritimecloud.idreg.keycloak-project-users-admin-user=idreg-admin
net.maritimecloud.idreg.keycloak-project-users-admin-password=idreg-admin
net.maritimecloud.idreg.keycloak-project-users-admin-client=security-admin-console
net.maritimecloud.idreg.keycloak-project-users-realm=master
net.maritimecloud.idreg.keycloak-project-users-base-url=http://localhost:9080/auth/
```

To setup an organization with its own Identity Provider, the Identity Registry can automatically set it up using a few extra attributes in the organization json when creating it. See ```setup/testidp.json``` for an example. The Identity Provider must support OpenID Connect and have set up a client. The client id and secret is 2 of the needed attributes for Identity Provider registration, the last one is a link to the "well-known url", as defined in the [OpenID Connect Discovery Specs](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

## Login using certificates
To login using certificates a client certificate must first be generated and signed by the MaritimeCloud Identity Registry. For a vessel it can be done like this:
```sh
$ curl -b cookies.txt -k https://localhost:8443/admin/api/org/DMA/vessel/1/generatecertificate
```

This will return a public key, private key and a certificate in PEM format for this vessel signed by the MaritimeCloud, and should be saved locally. The certificate is saved in the Identity Registry, but the keys is not.

If the private key is stored in ```ship-private.pem``` and the certificate in ```ship-cert.pem```, an example of use could be this:
```sh
$ curl -i -k https://localhost:8443/x509/api/org/DMA/vessel/2 --key ship-private.pem --cert ship-cert.pem
```
