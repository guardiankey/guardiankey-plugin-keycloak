# Stage 1: build the plugin JAR with Maven
FROM maven:3.8-openjdk-11 AS builder
WORKDIR /build
COPY pom.xml .
# Download dependencies first (layer cache)
RUN mvn dependency:go-offline -q
COPY src/ src/
RUN mvn package -DskipTests -q

# Stage 2: Keycloak with plugin installed
FROM quay.io/keycloak/keycloak:18.0.0

COPY --from=builder /build/target/guardiankey-keycloak-plugin-*.jar /opt/keycloak/providers/
COPY themes/ /opt/keycloak/themes/

# Re-augment Keycloak with the new provider
RUN /opt/keycloak/bin/kc.sh build
