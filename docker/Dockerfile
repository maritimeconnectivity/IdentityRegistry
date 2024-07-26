# Run like this:
# sudo docker run -t -i --rm -p 8443:8443 -v /path/to/config-directory/on/machine:/conf <image-id>
#
# A customized conf file (application.yaml) must be available in the folder mounted to /conf.
# When using in non-local environment it is recommened to generate new trust and keystores and place them in
# the conf-folder and point to them in application.yaml.

FROM eclipse-temurin:21-jdk AS builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libapr1-dev libssl-dev tar gzip build-essential file && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

ADD https://dlcdn.apache.org/tomcat/tomcat-connectors/native/2.0.7/source/tomcat-native-2.0.7-src.tar.gz tomcat-native.tar.gz

RUN tar -xvf tomcat-native.tar.gz && mv tomcat-native*/ tomcat-native/

WORKDIR tomcat-native/native

RUN ./configure && make && make install

FROM eclipse-temurin:21-jre

LABEL org.opencontainers.image.source="https://github.com/maritimeconnectivity/IdentityRegistry"

ENV MARIADB_VERSION=3.3.3
ENV MYSQL_VERSION=8.3.0
ENV LOADER_PATH=/modules

COPY --from=builder /usr/local/apr/lib /usr/lib/

RUN mkdir /conf

RUN mkdir $LOADER_PATH

# Download the MariaDB client connector from Maven Central
ADD https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/$MARIADB_VERSION/mariadb-java-client-$MARIADB_VERSION.jar $LOADER_PATH

# Download the MySQL client connector from Maven Central
ADD https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/$MYSQL_VERSION/mysql-connector-j-$MYSQL_VERSION.jar $LOADER_PATH

# Install native libraries that can be used by Spring Boot's embedded Tomcat server for improved performance
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libapr1 && rm -rf /var/lib/apt/lists* /var/cache/apt/archives/*

ADD mcp-identityregistry-core-latest.jar .

EXPOSE 8443

CMD ["java", "-Dspring.profiles.active=docker", "-jar", "mcp-identityregistry-core-latest.jar", "--spring.config.location=/conf/application.yaml"]
