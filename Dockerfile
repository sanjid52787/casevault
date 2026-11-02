# syntax=docker/dockerfile:1
# Specific, maintained Java 21 images. Renovate/Dependabot should review tag updates.
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod 0555 mvnw && ./mvnw -B -q dependency:go-offline
COPY src/ src/
RUN ./mvnw -B -DskipTests package \
 && java -Djarmode=tools -jar target/casevault-0.0.1-SNAPSHOT.jar extract --layers --destination /layers

FROM eclipse-temurin:21-jre-jammy AS runtime
RUN apt-get update \
 && apt-get install --no-install-recommends -y curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 casevault \
 && useradd --uid 10001 --gid 10001 --home-dir /opt/casevault --shell /usr/sbin/nologin casevault \
 && mkdir -p /opt/casevault /var/lib/casevault/evidence \
 && chown -R casevault:casevault /opt/casevault /var/lib/casevault
WORKDIR /opt/casevault
COPY --from=build --chown=casevault:casevault /layers/dependencies/ ./
COPY --from=build --chown=casevault:casevault /layers/spring-boot-loader/ ./
COPY --from=build --chown=casevault:casevault /layers/snapshot-dependencies/ ./
COPY --from=build --chown=casevault:casevault /layers/application/ ./
COPY --chown=casevault:casevault deploy/scripts/docker-entrypoint.sh /opt/casevault/entrypoint.sh
RUN chmod 0550 /opt/casevault/entrypoint.sh

USER 10001:10001
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:InitialRAMPercentage=25 -XX:+ExitOnOutOfMemoryError -Djava.security.egd=file:/dev/urandom"
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD curl --fail --silent http://127.0.0.1:8080/actuator/health || exit 1
ENTRYPOINT ["/opt/casevault/entrypoint.sh"]
