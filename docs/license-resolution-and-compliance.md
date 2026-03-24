# License Resolution and Compliance

This document describes the license analysis features that help you understand your project's license and check compatibility with your dependencies.

## Overview

License analysis is **enabled by default** and provides:

1. **Project license detection** from your manifest file (e.g., `pom.xml`, `package.json`, `Cargo.toml`) and LICENSE files
2. **Dependency license information** from the Trustify DA backend
3. **Compatibility checking** to identify potential license conflicts
4. **Mismatch detection** when your manifest and LICENSE file declare different licenses

## How It Works

### Project License Detection

The client looks for your project's license with **automatic fallback**:

1. **Primary: Manifest file** — Reads the license field from:
   - `pom.xml`: `<licenses><license><name>` element
   - `package.json`: `license` field (or legacy `licenses` array)
   - `Cargo.toml`: `package.license` field
   - `build.gradle` / `build.gradle.kts`: No standard license field (falls back to LICENSE file)
   - `go.mod`: No standard license field (falls back to LICENSE file)
   - `requirements.txt`: No standard license field (falls back to LICENSE file)

2. **Fallback: LICENSE file** — If no license is found in the manifest, searches for `LICENSE`, `LICENSE.md`, or `LICENSE.txt` in the same directory as your manifest

**How the fallback works:**
- **Ecosystems with manifest license support** (Maven, JavaScript, Cargo): Uses manifest license if present, otherwise falls back to LICENSE file
- **Ecosystems without manifest license support** (Gradle, Go, Python): Automatically reads from LICENSE file
- **SPDX detection**: Common licenses (Apache-2.0, MIT, GPL-2.0/3.0, LGPL-2.1/3.0, AGPL-3.0, BSD-2-Clause/3-Clause) are automatically detected from LICENSE file content

The backend's license identification API (`POST /api/v5/licenses/identify`) is used for more accurate LICENSE file detection when available.

### Compatibility Checking

The client checks if dependency licenses are compatible with your project license using a restrictiveness hierarchy:

```
PERMISSIVE (1) < WEAK_COPYLEFT (2) < STRONG_COPYLEFT (3)
```

- If a dependency's license is **more restrictive** than the project → **INCOMPATIBLE**
- If a dependency's license is **equal or less restrictive** → **COMPATIBLE**
- If either license category is **UNKNOWN** → **UNKNOWN**

Examples:
- Permissive project (MIT) + permissive dependency (Apache-2.0) → Compatible
- Permissive project (MIT) + strong copyleft dependency (GPL-3.0) → Incompatible
- Strong copyleft project (GPL-3.0) + permissive dependency (MIT) → Compatible

## Configuration

### Disable License Checking

License analysis runs automatically during **component analysis only** (not stack analysis). To disable it:

**Environment variable:**
```bash
export TRUSTIFY_DA_LICENSE_CHECK=false
```

**Java property:**
```java
System.setProperty("TRUSTIFY_DA_LICENSE_CHECK", "false");
```

## CLI Usage

### License Command

Display project license information from manifest and LICENSE file:

```bash
java -jar trustify-da-java-client-cli.jar license /path/to/pom.xml
```

**Example output:**
```json
{
  "manifestLicense": {
    "spdxId": "Apache-2.0",
    "details": {
      "identifiers": [
        {
          "id": "Apache-2.0",
          "name": "Apache License 2.0",
          "isDeprecated": false,
          "isOsiApproved": true,
          "isFsfLibre": true,
          "category": "PERMISSIVE"
        }
      ],
      "expression": "Apache-2.0",
      "name": "Apache License 2.0",
      "category": "PERMISSIVE",
      "source": "SPDX",
      "sourceUrl": "https://spdx.org"
    }
  },
  "mismatch": false
}
```

> Note: `fileLicense` is omitted when null. The `license` command shows only your project's license. For dependency license compatibility, use component analysis.

### Component Analysis with License Summary

When running component analysis, the license summary is automatically included in the output:

```bash
java -jar trustify-da-java-client-cli.jar component /path/to/pom.xml
```

## Programmatic Usage

```java
import io.github.guacsec.trustifyda.ComponentAnalysisResult;
import io.github.guacsec.trustifyda.impl.ExhortApi;
import io.github.guacsec.trustifyda.license.LicenseCheck.LicenseSummary;

ExhortApi api = new ExhortApi();

// Run component analysis with license check
ComponentAnalysisResult result = api.componentAnalysisWithLicense("/path/to/pom.xml").get();

// Access the analysis report
var report = result.report();

// Access the license summary
LicenseSummary licenseSummary = result.licenseSummary();
if (licenseSummary != null) {
    // Project license info
    var projectLicense = licenseSummary.projectLicense();
    System.out.println("Mismatch: " + projectLicense.mismatch());

    // Incompatible dependencies
    for (var dep : licenseSummary.incompatibleDependencies()) {
        System.out.println("Incompatible: " + dep.purl() + " - " + dep.licenses());
    }
}

// Or use componentAnalysis() without license check (original API, unchanged)
var reportOnly = api.componentAnalysis("/path/to/pom.xml").get();
```

## License Summary Fields

The `LicenseSummary` returned in `ComponentAnalysisResult.licenseSummary()` contains:

| Field | Type | Description |
|-------|------|-------------|
| `projectLicense` | `ProjectLicenseSummary` | Project license from manifest and LICENSE file |
| `incompatibleDependencies` | `List<IncompatibleDependency>` | Dependencies with incompatible licenses |
| `error` | `String` | Error message if license check partially failed |

**ProjectLicenseSummary:**

| Field | Type | Description |
|-------|------|-------------|
| `manifest` | `JsonNode` | Full license details from backend for the manifest license (includes identifiers, category, name, source) |
| `file` | `JsonNode` | Full license details from backend for the LICENSE file license |
| `mismatch` | `boolean` | True if manifest and file licenses differ |

**IncompatibleDependency:**

| Field | Type | Description |
|-------|------|-------------|
| `purl` | `String` | Package URL of the dependency |
| `licenses` | `List<LicenseIdentifier>` | Full license identifier objects (id, name, category, isDeprecated, isOsiApproved, isFsfLibre) |
| `category` | `LicenseCategory` | License category |
| `reason` | `String` | Explanation of the incompatibility |

## SBOM Integration

Project license information is automatically included in generated CycloneDX SBOMs on the root component:

```json
{
  "metadata": {
    "component": {
      "type": "application",
      "name": "my-project",
      "version": "1.0.0",
      "licenses": [
        { "license": { "id": "Apache-2.0" } }
      ]
    }
  }
}
```

- **All ecosystems** include license information in the SBOM when available
- License names are resolved to valid SPDX identifiers using the CycloneDX license resolver
- If neither manifest nor LICENSE file contains a license, the SBOM root component will have no `licenses` field

## Common Scenarios

### Mismatch Between Manifest and LICENSE File

If your `pom.xml` says `Apache-2.0` but your LICENSE file contains MIT text:

```json
{
  "projectLicense": {
    "manifest": {
      "expression": "Apache-2.0",
      "category": "PERMISSIVE"
    },
    "file": {
      "expression": "MIT",
      "category": "PERMISSIVE"
    },
    "mismatch": true
  }
}
```

**Action:** Update your manifest or LICENSE file to match.

### Incompatible Dependencies

If you have a permissive-licensed project (e.g., Apache-2.0) but depend on copyleft-licensed libraries:

```json
{
  "incompatibleDependencies": [
    {
      "purl": "pkg:maven/org.mariadb.jdbc/mariadb-java-client@3.1.4",
      "licenses": [
        {
          "id": "LGPL-2.1",
          "name": "GNU Lesser General Public License v2.1 only",
          "isDeprecated": true,
          "isOsiApproved": true,
          "isFsfLibre": true,
          "category": "WEAK_COPYLEFT"
        }
      ],
      "category": "WEAK_COPYLEFT",
      "reason": "Dependency license(s) are incompatible with the project license."
    }
  ]
}
```

**Action:** Review the flagged dependencies and consider finding alternatives with compatible licenses.
