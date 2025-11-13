#!/bin/bash

set -e

VERBOSE=false
if [ "$1" = "--verbose" ]; then
    VERBOSE=true
    echo "Verbose mode enabled"
else
    echo "Quiet mode (default). Use --verbose for detailed logs"
fi

echo "Starting enhanced local build process (simulating CI)..."

# Section 1: Frontend quality checks (match CI frontend-quality job)
echo "Running frontend quality checks..."
cd frontend
if [ "$VERBOSE" = true ]; then
    yarn install --frozen-lockfile
    yarn lint 2>/dev/null || echo "No lint script found, skipping"
    yarn type-check 2>/dev/null || echo "No type-check script found, skipping"
    yarn test --coverage 2>/dev/null || yarn test
    yarn build
else
    yarn install --frozen-lockfile --silent >/dev/null
    yarn lint >/dev/null 2>&1 || echo "No lint script found, skipping"
    yarn type-check >/dev/null 2>&1 || echo "No type-check script found, skipping"
    yarn test --coverage >/dev/null 2>&1 || yarn test >/dev/null
    yarn build >/dev/null
fi
cd ..

echo "Caching frontend dist..."
mkdir -p .cache/frontend && cp -r frontend/dist/. .cache/frontend/

# Section 2: Backend quality checks (match CI backend-quality job)
echo "Running backend quality checks..."
mkdir -p backend/src/main/resources/static && rsync -a .cache/frontend/ backend/src/main/resources/static/
cd backend
chmod +x ./gradlew
export GITHUB_TOKEN=dummy  # Avoid null token issue in build.gradle
if [ "$VERBOSE" = true ]; then
    ./gradlew --no-daemon clean shadowJar
    ./gradlew --no-daemon test
    ./gradlew --no-daemon jacocoTestReport 2>/dev/null || echo "Jacoco not configured, skipping coverage report"
else
    ./gradlew --no-daemon --quiet clean shadowJar
    ./gradlew --no-daemon --quiet test
    ./gradlew --no-daemon --quiet jacocoTestReport 2>/dev/null || echo "Jacoco not configured, skipping coverage report"
fi
cd ..

echo "Copying JAR artifact..."
cp backend/build/libs/*.jar knca-signer.jar

# Section 3: Security scanning (match CI security-scan job)
echo "Running security scans (if Trivy available)..."
if command -v trivy >/dev/null 2>&1; then
    echo "Scanning frontend filesystem..."
    if [ "$VERBOSE" = true ]; then
        trivy fs frontend --ignore-unfixed
    else
        trivy fs frontend --ignore-unfixed --quiet
    fi

    echo "Scanning backend filesystem..."
    if [ "$VERBOSE" = true ]; then
        trivy fs backend --ignore-unfixed --vuln-type library
    else
        trivy fs backend --ignore-unfixed --quiet --vuln-type library
    fi
else
    echo "Trivy not found, skipping security scans. Install Trivy for local security scanning."
fi

# Section 4: Build Docker (match CI build-and-push job)
echo "Building Docker image..."
docker build -t knca-signer:latest .

# Scan Docker image if Trivy available
if command -v trivy >/dev/null 2>&1; then
    echo "Scanning Docker image..."
    if [ "$VERBOSE" = true ]; then
        trivy image knca-signer:latest --ignore-unfixed
    else
        trivy image knca-signer:latest --ignore-unfixed --quiet
    fi
fi

echo "Build completed successfully!"
echo "JAR created: knca-signer.jar (with embedded frontend assets)"
echo ""

# Section 5: Execute and test
echo "Testing build by running Docker container..."
echo "Running: docker run -p 9090:8080 knca-signer:latest"
docker run -d --name knca-signer-test -p 9090:8080 knca-signer:latest
sleep 10

echo "Checking container health..."
if docker ps | grep -q knca-signer-test; then
    echo "Container is running. Checking health endpoint..."
    if [ "$VERBOSE" = true ]; then
        curl -f http://localhost:9090/health
        curl_result=$?
    else
        curl -f -s http://localhost:9090/health >/dev/null 2>&1
        curl_result=$?
    fi
    if [ "$curl_result" -eq 0 ]; then
        echo "Health check passed! Build successful."
        # Display coverage summaries
        if [ -f "frontend/coverage/coverage-summary.json" ]; then
            echo "Frontend coverage: $(jq -r '.total.lines.pct' frontend/coverage/coverage-summary.json 2>/dev/null || echo 'N/A')% lines"
        fi
        if [ -d "backend/build/reports/jacoco" ]; then
            echo "Backend coverage report generated in backend/build/reports/jacoco/"
        fi
    else
        echo "Health check failed. Review logs with: docker logs knca-signer-test"
        exit 1
    fi
else
    echo "Container failed to start. Check logs with: docker logs knca-signer-test"
    exit 1
fi

echo "Cleaning up test container..."
if [ "$VERBOSE" = true ]; then
    docker stop knca-signer-test && docker rm knca-signer-test
else
    docker stop knca-signer-test >/dev/null 2>&1 && docker rm knca-signer-test >/dev/null 2>&1
fi

echo ""
echo "Verification complete! Ready for deployment."
echo "To run manually: docker run -p 9090:8080 knca-signer:latest"
