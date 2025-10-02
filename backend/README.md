### KNCA Signer Backend

A Bazel-based Java application for issuing chained certificates according to NCA certificate chains (default algorithm:
GOST 34.10–2015 512 bits).

The application provides:

- Certificate generation and validation
- Vert.x-based signature server
- WebSocket support for real-time operations

## Dependencies

### Optional Kalkan Cryptography Library

This project uses the Kalkan cryptography library for Kazakhstani digital signature operations. Due to licensing
restrictions, the Kalkan JAR files are not included in the repository and must be obtained separately.

**Building without Kalkan (default):**

- The project compiles without Kalkan JARs
- Kalkan-dependent features will throw runtime exceptions when accessed
- Suitable for development and testing environments

**Building with Kalkan:**

- Requires Kalkan JAR files to be placed in `backend/lib/`
- Enables full cryptographic functionality
- Required for production deployment

## Building and Running

This project uses Gradle for build management. Make sure Java 21 and Gradle are installed on your system.

### Quick Start

```bash
# Build the application (without Kalkan by default)
./gradlew build

# Build with Kalkan support (Kalkan JARs must be present in lib/)
./gradlew build

# Run tests
./gradlew test

# Run the application
./gradlew run

# Clean build artifacts
./gradlew clean
```

### IntelliJ IDEA Integration

This project is configured for use with IntelliJ IDEA via Gradle:

1. **Import the Project:**
    - Open IntelliJ IDEA
    - Select "File" → "Open"
    - Navigate to the `backend/` directory and select it
    - IDEA should automatically detect the Gradle project

2. **Gradle Configuration:**
    - The project uses `build.gradle` for configuration
    - JDK 21 is configured automatically
    - Dependencies are managed through Maven Central

3. **Building and Running:**
    - Use IDEA's built-in Gradle integration
    - Build tasks are available in the Gradle tool window
    - Run configurations can be created for the main application

### Manual Gradle Commands

```bash
# Build without Kalkan (default)
./gradlew build

# Build with Kalkan support (JARs in lib/ are auto-detected)
./gradlew build

# Run tests
./gradlew test

# Run the application
./gradlew run

# Create distribution archives
./gradlew distTar
./gradlew distZip
```

### Kalkan JAR Files

To enable Kalkan functionality, place the following JAR files in the `backend/lib/` directory:

- `kalkancrypt-0.7.5.jar`
- `kalkancrypt_xmldsig-0.4.jar`
- `knca_provider_util-0.8.6.jar`

These files are loaded at runtime and are not required for compilation.

## Project Structure

```
backend/
├── build.gradle          # Gradle build configuration
├── settings.gradle       # Gradle settings
├── gradlew               # Gradle wrapper script
├── gradle/wrapper/       # Gradle wrapper files
├── main/java/            # Main application code
├── test/java/            # Test code
├── lib/                  # Local JAR dependencies (Kalkan)
├── certs/                # Certificate files
└── build/                # Build output directory (generated)
```
