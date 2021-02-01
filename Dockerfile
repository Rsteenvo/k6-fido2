FROM tomcat:8.5.61-jdk11-openjdk
RUN rm -rf /usr/local/tomcat/webapps/ROOT
COPY ./target/*.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
