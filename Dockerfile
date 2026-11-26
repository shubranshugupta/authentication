# syntax=docker/dockerfile:1
#
# The app as a container image (F4):
#   docker build -t authcore .
# Runs with the prod profile, so every setting must come from the environment (see
# README.md). The API listens on 8080; health checks and metrics on 8081 (keep that
# one inside your network).
#
# The tests don't run here: they need Docker themselves. CI runs them before building.

# ---- build ----
FROM eclipse-temurin:25-jdk AS build
WORKDIR /build

# Dependencies first: they change less often than the code, so this layer stays cached.
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -q dependency:go-offline

COPY src/ src/
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -q package -DskipTests \
    && mv target/auth-*.jar app.jar

# One layer per kind of content (libraries, Spring Boot's launcher, the app), so that a
# code change only replaces the small last one.
RUN java -Djarmode=tools -jar app.jar extract --layers --launcher --destination extracted

# ---- run ----
FROM eclipse-temurin:25-jre

# Never as root.
RUN groupadd --system app && useradd --system --gid app --no-create-home app
WORKDIR /app

COPY --from=build /build/extracted/dependencies/ ./
COPY --from=build /build/extracted/spring-boot-loader/ ./
COPY --from=build /build/extracted/snapshot-dependencies/ ./
COPY --from=build /build/extracted/application/ ./

USER app
ENV SPRING_PROFILES_ACTIVE=prod
EXPOSE 8080 8081

# Uses up to 75 % of the container's memory limit for the heap.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "org.springframework.boot.loader.launch.JarLauncher"]
