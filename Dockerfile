FROM openjdk:21-slim

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    TZ=Asia/Almaty \
    JAVA_OPTS="-XX:+UseG1GC -XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.awt.headless=true -Djava.security.egd=file:/dev/urandom -Dfile.encoding=UTF-8 -DpreferIPv4Stack=true" \
    HTTP_PORT="8080" \
    HTTP_HOST="0.0.0.0" \
    WEBSOCKET_PATH="/ws" \
    STATIC_CONFIG_WEB_ROOT="static" \
    LOGGING_LEVEL="WARN" \
    CERTIFICATE_STORAGE_MODE="file" \
    CERTIFICATE_CERTS_PATH="/app/certs/" \
    CERTIFICATE_CA_CERT_PATH="/app/certs/ca.crt"

WORKDIR /app

# Create non-root user
RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup && \
    # Install necessary packages for locale and timezone
    apt-get update && apt-get install -y --no-install-recommends \
        locales \
        tzdata \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    # Generate locales
    && locale-gen en_US.UTF-8 \
    && ln -sf /usr/share/zoneinfo/Asia/Almaty /etc/localtime && echo "Asia/Almaty" > /etc/timezone

# Copy the pre-built JAR (built in CI)
COPY knca-signer.jar app.jar

# Set ownership
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f -s http://localhost:8080/health || exit 1

# Note: For full functionality, mount Kalkan JARs to /app/lib at runtime
CMD ["sh", "-c", "java $JAVA_OPTS -cp 'app.jar:/app/lib/*' knca.signer.App"]
