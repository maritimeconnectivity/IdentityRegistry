FROM dmadk/mc-identity-registry-api

ADD yubihsm_pkcs11.conf .
ADD pkcs11_yubi.cfg /conf

# Download and install the SDK for the YubiHSM 2
WORKDIR /tmp
RUN wget https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-2019-12-debian10-amd64.tar.gz
RUN tar -xvf yubihsm2-sdk-2019-12-debian10-amd64.tar.gz
RUN apt update && apt install -y ./yubihsm2-sdk/*.deb
RUN rm -rf /tmp/yubihsm2* && rm -rf /var/lib/apt/lists/*

WORKDIR /

EXPOSE 8443

CMD ["java", "-jar", "mcp-identityregistry-core-latest.war", "--spring.config.location=/conf/application.yaml", "--keycloak.configurationFile=file:/conf/keycloak.json"]
