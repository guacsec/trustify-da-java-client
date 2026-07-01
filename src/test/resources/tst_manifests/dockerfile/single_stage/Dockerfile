FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4

RUN microdnf install -y java-17-openjdk-headless && microdnf clean all

COPY target/app.jar /app.jar
CMD ["java", "-jar", "/app.jar"]
