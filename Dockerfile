FROM java:8
COPY ./target/*.jar /root/cryto-service.jar
WORKDIR /root
EXPOSE 8080
CMD ["java", "-jar", "cryto-service.jar"]