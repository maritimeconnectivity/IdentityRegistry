# Maritime Cloud Identity Registry (test implementation)
This is a test implementation of the Maritime Cloud Identity Registry. It is expected to be changed and rewritten a number of times before being useful to anyone. It is under the Apache 2.0 License.

## Setup Database
A MySQL/MariaDB is used as datastore, it can be setup running this commands from the console:
```sh
$ ./setup/setup-db.sh
```
You will be prompted for the root password for the database. The script will create a new user and this user will be used to create the needed tables.

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
First an Organization must be added. It can be done like this using curl from the console:
```sh
$ curl -H "Content-Type: application/json" --data @setup/dma.json http://localhost:8080/api/org/apply
```

This will return some json looking like this, which is mostly an echo of the posted json:
```json
{"id":1,"createdAt":1448544528797,"updatedAt":1448544528797,"name":"Danish Maritime Authority","shortName":"DMA","url":"http://www.soefartsstyrelsen.dk/","country":"Denmark","password":"iklugohe4agngesqpv3c4jm34g"}
```

So now an Organization named "Danish Maritime Authority" has been created. Make a note of the "shortName" and "password" since they will be used for authentication, which is the next step:
```sh
$ curl -i -X POST -d username=DMA -d password=iklugohe4agngesqpv3c4jm34g -c ./cookies.txt http://localhost:8080/login
```
Change the username and password as needed. A authentication token will be saved into the file cookies.txt, and can now be used to access the API.

To create some ships for Organization with id 1, do this:
```sh
$ curl -H "Content-Type: application/json" -b cookies.txt --data @setup/ship1.json http://localhost:8080/api/ship
$ curl -H "Content-Type: application/json" -b cookies.txt --data @setup/ship2.json http://localhost:8080/api/ship
```

Each command will (mostly) return an echo of the json posted to the api:
```json
{"id":1,"createdAt":1448545611826,"updatedAt":1448545611826,"idOrganization":1,"shipOrgId":"dma1","name":"POUL LØWENØRN","attributes":[{"id":1,"createdAt":1448545611838,"updatedAt":1448545611838,"attributeName":"IMO number","attributeValue":"9250969"},{"id":2,"createdAt":1448545611840,"updatedAt":1448545611840,"attributeName":"callsign","attributeValue":"OZZX"},{"id":3,"createdAt":1448545611844,"updatedAt":1448545611844,"attributeName":"Port Of Register","attributeValue":"KØBENHAVN"}],"certificates":[{"id":1,"createdAt":1448545612001,"updatedAt":1448545612001,"certificate":"MIIExTCCBCagAwIBAgIJANFvAwTi8bHQMAoGCCqGSM49BAMCMIGZMQswCQYDVQQGEwJESzETMBEGA1UECAwKU29tZS1TdGF0ZTEVMBMGA1UEBwwMS8ODwrhiZW5oYXZuMSIwIAYDVQQKDBlEYW5pc2ggTWFyaXRpbWUgQXV0aG9yaXR5MRwwGgYDVQQLDBNQT1VMIEzDg8KYV0VOw4PCmFJOMRwwGgYDVQQDDBNQT1VMIEzDg8KYV0VOw4PCmFJOMB4XDTE1MTEyMzEyMTA0NVoXDTE3MTEyMjEyMTA0NVowgZkxCzAJBgNVBAYTAkRLMRMwEQYDVQQIDApTb21lLVN0YXRlMRUwEwYDVQQHDAxLw4PCuGJlbmhhdm4xIjAgBgNVBAoMGURhbmlzaCBNYXJpdGltZSBBdXRob3JpdHkxHDAaBgNVBAsME1BPVUwgTMODwphXRU7Dg8KYUk4xHDAaBgNVBAMME1BPVUwgTMODwphXRU7Dg8KYUk4wggJcMIIBzwYHKoZIzj0CATCCAcICAQEwTQYHKoZIzj0BAQJCAf//////////////////////////////////////////////////////////////////////////////////////MIGeBEIB//////////////////////////////////////////////////////////////////////////////////////wEQVGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ4VYZOVHsfpN7FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8AAxUA0J6IACkcuFOWzGcXOTKEqqDaZLoEgYUEAMaFjga3BATpzZ4+y2YjlbRCnGSBOQU/tSH4KK9ga009uqFLXnfv51ko/h3BJ6L/qN4zSLPBhWpCm/l+fjHC5b1mARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT+tB2E1PHCGonLCQIi+lHaf0WZQAkIB///////////////////////////////////////////6UYaHg78vlmt/zAFI9wml0Du1ybiJnEeuu2+3HpE4ZAkCAQEDgYYABAFtUwGR5BVsFiavE3iMcQtxhwfMSia9/1HXdbfEYcSIuJG9kG5yLDhA0xtmYLbwTqfAW6BA/0f1LKUv3zumXYTQgACuwivyGPRu3g3M4FJxQixYq8BzY6H8JT7dutL1hEKJhEkPCXafeWsFxWDqa8BFiVJTBqc9vHH37lkWG0d0+oVlHaNQME4wHQYDVR0OBBYEFPdfJOe9cM92Xf/3tiCtlQ3NoeilMB8GA1UdIwQYMBaAFPdfJOe9cM92Xf/3tiCtlQ3NoeilMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDgYwAMIGIAkIB4ONcDL8Gfginj/6GeyhJe5OAQwstjXe+kZd59/M3VFwJRLvDK6i1VCnWQVw9iSwpVGdCJXSaW3nP870OOLwGErcCQgGOEpH16mlHxhdZJRhNnwQwQTZd1dbMEagpQWFflOfS9ZQQ/aAli1XdH05E5OBf6o1UZjD0sod990AYDapk1jN3fg=="}]}
```
