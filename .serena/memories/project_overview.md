# exhort-java-api Project Overview

## Purpose
Java client library for the Dependency Analytics (DA) / Exhort vulnerability analysis backend. Generates SBOMs (CycloneDX JSON) from project manifests and submits them for analysis.

## Tech Stack
- Java 17+, Maven build
- Jackson for JSON, TOML parsing (com.moandjiezana.toml)
- XMLStreamReader for POM parsing
- CycloneDX SBOM model (custom `Sbom` class)

## Key Directories
- `src/main/java/io/github/guacsec/trustifyda/providers/` - Provider implementations per ecosystem
- `src/main/java/io/github/guacsec/trustifyda/tools/` - Utilities (Operations, Ecosystem, Environment)
- `src/main/java/io/github/guacsec/trustifyda/utils/` - Shared utilities (IgnorePatternDetector, PythonControllerBase)
- `src/test/resources/tst_manifests/` - Test fixtures per ecosystem

## Provider Pattern
Each ecosystem has a Provider class extending `Provider` abstract class with methods:
- `provideStack()` - Full dependency tree SBOM
- `provideComponent()` - Direct dependencies only SBOM
- `readLicenseFromManifest()` - License extraction
- `validateLockFile(Path)` - Lock file validation

## Ignore Pattern Detection
Centralized in `IgnorePatternDetector` with constants `IGNORE_PATTERN` ("trustify-da-ignore") and `LEGACY_IGNORE_PATTERN` ("exhortignore").

## Commands
- Build: `mvn clean install`
- Test: `mvn test`
- Format: `mvn spotless:apply`
