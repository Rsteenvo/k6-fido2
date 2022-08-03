FROM docker-proxy.backbase.eu/dockerhub/library/tomcat:8.5.81-jre17-temurin
RUN rm -rf /usr/local/tomcat/webapps/ROOT
COPY ./target/*.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
