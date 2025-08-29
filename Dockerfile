FROM gradle:7.6-jdk17 as builder
WORKDIR /app
COPY . .
RUN gradle build --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar

# Add a healthcheck
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/actuator/health || exit 1

# Security: run as non-root user
RUN addgroup --system --gid 1001 appuser && \
    adduser --system --uid 1001 --ingroup appuser appuser
USER appuser

ENTRYPOINT ["java", "-jar", "app.jar"]