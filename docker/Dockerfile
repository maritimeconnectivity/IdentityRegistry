# Run like this:
# sudo docker run -t -i --rm -p 8443:8443 -v /path/to/config-directory/on/machine:/conf <image-id>
# 
# A customized conf file (application.yaml) must be available in the folder mounted to /conf.
# When using in non-local environment it is recommened to generate new trust and keystores and place them in
# the conf-folder and point to them in application.yaml.
FROM openjdk:8-jre

RUN mkdir -p /conf
ADD mc-identityregistry-core-latest.war .

# Set locales for image to support UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

EXPOSE 8443

CMD ["java", "-Dspring.profiles.active=docker", "-jar", "mcp-identityregistry-core-latest.war", "--spring.config.location=/conf/application.yaml", "--keycloak.configurationFile=file:/conf/keycloak.json"]
