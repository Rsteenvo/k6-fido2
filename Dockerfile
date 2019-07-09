FROM java:8
COPY ./target/test-app-0.0.1-SNAPSHOT.jar /root/test-app.jar
WORKDIR /root
EXPOSE 8080
CMD ["java", "-jar", "test-app.jar"]