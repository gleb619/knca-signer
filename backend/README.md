# KNCA Signer Backend

A Java 21 web application for digital signature operations and certificate management according to Kazakhstani NCA
standards (GOST 34.10-2015 512-bit algorithms).

## Overview

The application provides:

- Certificate Authority (CA), user, and legal entity certificate generation
- XML digital signature creation and verification
- REST API endpoints for certificate operations
- Vert.x-based asynchronous web server

## Architecture

The backend is built using:

- **Vert.x**: Asynchronous, event-driven web framework
- **Java 21**: Modern Java with latest language features
- **Gradle**: Build automation and dependency management
- **ByteBuddy**: Runtime bytecode manipulation for proxy creation
- **Kalkan Integration**: Cryptographic operations via reflection proxies

### Key Components

- `App.java`: Main Vert.x verticle with HTTP server setup
- `CertificateHandler.java`: REST endpoints for certificate operations
- `SigningHandler.java`: XML signing and verification endpoints
- `kalkan/` package: Reflection-based Kalkan cryptography library integration

## Dependencies

### Core Dependencies

- **Vert.x Core/Web**: 4.4.6 - Web framework and server
- **Jackson**: 2.15.2 - JSON processing
- **JavaTime Jackson Module**: Date/time serialization
- **Lombok**: 1.18.30 - Code generation annotations
- **SLF4J/Simple**: Logging framework

### Build & Test

- **JUnit 5/Jupiter**: 5.10.0 - Unit testing
- **Vert.x JUnit 5**: 4.4.6 - Vert.x testing utilities
- **Mockito**: 5.5.0 - Mocking framework

### Cryptography Integration

Due to license restrictions, we cannot use the Kalkan cryptography library directly through standard imports and
linkage. Instead, the application uses runtime reflection and ByteBuddy to create transparent proxies for Kalkan
classes, allowing full functionality without direct commercial licensing requirements.

**ByteBuddy Integration**:

- Runtime proxy generation for Kalkan classes
- Transparent method delegation
- Dynamic class loading and instantiation

**Reflection Helper**:

- Dynamic classpath scanning for Kalkan JARs
- Type-safe method invocation
- Exception handling and wrapping

### Optional Kalkan Cryptography Library

The project depends on the Kalkan cryptography library for Kazakhstani digital signature operations. However, due to
licensing restrictions:

- **Kalkan JARs are NOT included** in the repository
- **Direct imports are prohibited** due to commercial licensing
- **Runtime reflection + ByteBuddy proxies** are used instead
- Suitable for development/testing without Kalkan JARs (will throw exceptions when cryptographic operations are
  attempted)

**To enable full functionality:**

1. Obtain Kalkan JAR files separately:
    - `kalkancrypt-0.7.5.jar`
    - `kalkancrypt_xmldsig-0.4.jar`
    - `knca_provider_util-0.8.6.jar`
2. Place them in `backend/lib/` directory
3. The build system will auto-detect and include them

## Building and Running

Make sure Java 21 and Gradle are installed on your system.

### Prerequisites

- Java 21 (JDK)
- Gradle 7.0+ (or use included `./gradlew`)
- (Optional) Kalkan JARs in `backend/lib/`

### Quick Start

```bash
# Build the application
./gradlew build

# Run tests
./gradlew test

# Run the application
./gradlew run
```

### Development Commands

```bash
# Clean build artifacts
./gradlew clean

# Build without Kalkan (default)
./gradlew build

# Build with Kalkan support (auto-detected from lib/ directory)
./gradlew build

# Run integration tests
./gradlew test --tests "*IT"

# Create distribution archives
./gradlew distTar
./gradlew distZip

# Generate Gradle wrapper (if needed)
./gradlew wrapper
```

### IntelliJ IDEA Integration

This project is configured for IntelliJ IDEA:

1. **Import Project**: Open `backend/` directory in IDEA
2. **Gradle Sync**: IDE will auto-detect Gradle configuration
3. **JDK 21**: Ensure project SDK is set to Java 21
4. **Run Configurations**: Use built-in Gradle tasks or create Run/Debug for `App.main()`

### Application Execution

The server starts on the configured port (default: 8080):

```bash
# Direct execution
./gradlew run

# Or run from JAR
java -jar build/libs/backend.jar
```

**Default Configuration**:

- HTTP Port: 8080
- Static Files: Served from `src/main/resources/static/`

### Example Usage

Run certificate generation example:

```bash
./gradlew runGenerator
```

Run signature validation example:

```bash
./gradlew runValidator
```

## API Endpoints

### Certificate Management

All certificate endpoints return JSON responses.

```bash
# Get CA certificate
GET /api/certificates/ca

# Get user certificates
GET /api/certificates/user?caId=default

# Get legal entity certificates
GET /api/certificates/legal?caId=default

# Get certificates from filesystem storage
GET /api/certificates/filesystem

# Generate CA certificate
POST /api/certificates/generate/ca?alias=my-ca

# Generate user certificate
POST /api/certificates/generate/user
Content-Type: application/json
{
  "caId": "default"
}

# Generate legal entity certificate
POST /api/certificates/generate/legal
Content-Type: application/json
{
  "caId": "default"
}
```

### Signature Operations

```bash
# Sign XML data
POST /api/sign
Content-Type: application/json
{
  "data": "<xml>...</xml>",
  "certificate": "...",
  "key": "..."
}

# Verify signature
POST /api/verify
Content-Type: application/json
{
  "signature": "...",
  "data": "...",
  "certificate": "..."
}

# Validate XML signature
POST /api/validate/xml
Content-Type: application/json
{
  "xml": "<xml>...</xml>"
}
```

### Health Check

```bash
# Application health status
GET /health
```

## Testing

### Unit Tests

```bash
./gradlew test --tests "*Test"
```

### Integration Tests

```bash
./gradlew test --tests "*IT"
```

Tests use JUnit 5 and require real Kalkan provider for full functionality.

### Example Applications

Example classes for testing operations:

- `Generator.java`: Certificate generation example
- `Reader.java`: Certificate reading example
- `Validator.java`: Signature validation example

Run examples:

```bash
./gradlew runGenerator
./gradlew runReader
./gradlew runValidator
```

## License

This project is licensed under the MIT License. Note that the Kalkan cryptography library has separate licensing terms
that may require commercial licensing for production use. This application avoids direct Kalkan linkage through
reflection and proxy techniques to enable development and testing without licensing restrictions.
