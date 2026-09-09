# Run like this:
# sudo docker run -t -i --rm -p 8443:8443 -v /path/to/config-directory/on/machine:/conf <image-id>
#
# A customized conf file (application.yaml) must be available in the folder mounted to /conf.
# When using in non-local environment it is recommened to generate new trust and keystores and place them in
# the conf-folder and point to them in application.yaml.

FROM eclipse-temurin:25-jdk AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential file libapr1-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

ADD --checksum=sha256:785fdd99a202f442b085bc718d2fbeb393b85979aa4a2943302118c4acd68630 --unpack=true https://dlcdn.apache.org/tomcat/tomcat-connectors/native/2.0.16/source/tomcat-native-2.0.16-src.tar.gz .

RUN mv tomcat-native*/ tomcat-native/

WORKDIR tomcat-native/native

RUN ./configure && make && make install

FROM eclipse-temurin:25-jre

LABEL org.opencontainers.image.source="https://github.com/maritimeconnectivity/IdentityRegistry"

ENV MARIADB_VERSION=3.5.10
ENV MARIADB_CHECKSUM=919b8c1c771d9ee3465811462f242c9543ab401e140c64988ddbf1d8abcb18b2
ENV MYSQL_VERSION=9.7.0
ENV MYSQL_CHECKSUM=0353648eaa1c91e0f4020c959abf756bc866ffd583df22ae6b6f6e0cbd43eb44
ENV LOADER_PATH=/modules

RUN mkdir /usr/lib/tcnative

COPY --from=builder /usr/local/apr/lib /usr/lib/tcnative/

RUN mkdir /conf $LOADER_PATH

# Download the MariaDB client connector from Maven Central
ADD --checksum=sha256:$MARIADB_CHECKSUM https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/$MARIADB_VERSION/mariadb-java-client-$MARIADB_VERSION.jar $LOADER_PATH

# Download the MySQL client connector from Maven Central
ADD --checksum=sha256:$MYSQL_CHECKSUM https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/$MYSQL_VERSION/mysql-connector-j-$MYSQL_VERSION.jar $LOADER_PATH

# Install native libraries that can be used by Spring Boot's embedded Tomcat server for improved performance
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y libapr1 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY mcp-identityregistry-core-latest.jar .

EXPOSE 8443

CMD ["java", "-Dspring.profiles.active=docker", "-jar", "mcp-identityregistry-core-latest.jar", "--spring.config.location=/conf/application.yaml", "-Djava.library.path=/usr/lib/tcnative"]
