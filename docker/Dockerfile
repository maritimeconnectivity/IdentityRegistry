# Run like this:
# sudo docker run -t -i --rm -p 8443:8443 -v /path/to/config-directory/on/machine:/conf <image-id>
FROM java:8

RUN mkdir -p /conf
RUN wget "https://dma.ci.cloudbees.com/view/MaritimeCloud/job/MaritimeCloud%20Identity%20Registry%20API/lastSuccessfulBuild/artifact/target/mc-identityregistry-core-0.0.1-SNAPSHOT.war" -O mc-id-reg.war

EXPOSE 8443

CMD ["cat", "/conf/application.yaml"]
CMD ["java", "-Dspring.profiles.active=docker", "-jar", "mc-id-reg.war", "--spring.config.location=/conf/application.yaml"]
