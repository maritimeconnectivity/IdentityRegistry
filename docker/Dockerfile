# Run like this:
# sudo docker run -t -i --rm -p 8443:8443 -v /path/to/config-directory/on/machine:/conf <image-id>
# 
# A customized conf file (application.yaml) must be available in the folder mounted to /conf.
# When using in non-local environment it is recommened to generate new trust and keystores and place them in
# the conf-folder and point to them in application.yaml.
FROM java:8

RUN mkdir -p /conf
RUN wget "https://dma.ci.cloudbees.com/view/MaritimeCloud/job/MaritimeCloud%20Identity%20Registry%20API/lastSuccessfulBuild/artifact/target/mc-identityregistry-core-latest.war"

EXPOSE 8443

CMD ["java", "-Dspring.profiles.active=docker", "-jar", "mc-identityregistry-core-latest.war", "--spring.config.location=/conf/application.yaml", "--keycloak.config.file=/conf/keycloak.conf"]
