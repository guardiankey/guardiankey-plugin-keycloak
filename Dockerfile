# Stage 1: build the plugin JAR with Maven
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY pom.xml .
# Download dependencies first (layer cache)
RUN mvn dependency:go-offline -q
COPY src/ src/
RUN mvn package -DskipTests -q

# Stage 2: extract and patch template.ftl using the JDK 'jar' tool (no OS deps needed).
# We copy the Keycloak themes JAR into this Maven/JDK stage so we can use 'jar xf'.
FROM quay.io/keycloak/keycloak:26.2.5 AS kc-source

FROM maven:3.9-eclipse-temurin-17 AS patcher
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
COPY --from=kc-source /opt/keycloak/lib/lib/main/ /kc-lib/
COPY themes/ /themes/
RUN THEMES_JAR=$(ls /kc-lib/org.keycloak.keycloak-themes-*.jar | grep -v vendor | head -1) && \
    echo "Patching from: ${THEMES_JAR}" && \
    mkdir -p /tmp/jar-extract && \
    (cd /tmp/jar-extract && jar xf "${THEMES_JAR}" theme/base/login/template.ftl) && \
    mkdir -p /themes/custom/login && \
    cp /tmp/jar-extract/theme/base/login/template.ftl /themes/custom/login/template.ftl && \
    sed -i 's|</body>|<#if gktinc_javascript??>${gktinc_javascript?no_esc}</#if>\n</body>|' \
        /themes/custom/login/template.ftl && \
    echo "Patch applied."

# Stage 3: final Keycloak image with plugin and patched theme
FROM quay.io/keycloak/keycloak:26.2.5

COPY --from=builder /build/target/guardiankey-keycloak-plugin-*.jar /opt/keycloak/providers/
COPY --from=patcher /themes/ /opt/keycloak/themes/

RUN /opt/keycloak/bin/kc.sh build 