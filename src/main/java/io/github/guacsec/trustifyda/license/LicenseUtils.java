/*
 * Copyright 2023-2025 Trustify Dependency Analytics Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.guacsec.trustifyda.license;

import static io.github.guacsec.trustifyda.impl.ExhortApi.debugLoggingIsNeeded;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.api.v5.LicenseIdentifier;
import io.github.guacsec.trustifyda.api.v5.LicenseInfo;
import io.github.guacsec.trustifyda.api.v5.LicenseProviderResult;
import io.github.guacsec.trustifyda.api.v5.PackageLicenseResult;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class LicenseUtils {

  private static final Logger LOG = LoggersFactory.getLogger(LicenseUtils.class.getName());
  private static final List<String> LICENSE_FILES = List.of("LICENSE", "LICENSE.md", "LICENSE.txt");
  private static final Pattern APACHE_2_PATTERN =
      Pattern.compile("Apache License,?\\s*Version 2\\.0", Pattern.CASE_INSENSITIVE);
  private static final Pattern AGPL_3_PATTERN =
      Pattern.compile("GNU AFFERO GENERAL PUBLIC LICENSE\\s+Version 3", Pattern.CASE_INSENSITIVE);
  private static final Pattern LGPL_3_PATTERN =
      Pattern.compile("GNU LESSER GENERAL PUBLIC LICENSE\\s+Version 3", Pattern.CASE_INSENSITIVE);
  private static final Pattern LGPL_21_PATTERN =
      Pattern.compile(
          "GNU LESSER GENERAL PUBLIC LICENSE\\s+Version 2\\.1", Pattern.CASE_INSENSITIVE);
  private static final Pattern GPL_2_PATTERN =
      Pattern.compile("GNU GENERAL PUBLIC LICENSE\\s+Version 2", Pattern.CASE_INSENSITIVE);
  private static final Pattern GPL_3_PATTERN =
      Pattern.compile("GNU GENERAL PUBLIC LICENSE\\s+Version 3", Pattern.CASE_INSENSITIVE);
  private static final Pattern BSD_2_PATTERN =
      Pattern.compile("BSD 2-Clause", Pattern.CASE_INSENSITIVE);
  private static final Pattern BSD_3_PATTERN =
      Pattern.compile("BSD 3-Clause", Pattern.CASE_INSENSITIVE);
  private static final Pattern MIT_LICENSE_PATTERN =
      Pattern.compile("MIT License", Pattern.CASE_INSENSITIVE);
  private static final Pattern MIT_PERMISSION_PATTERN =
      Pattern.compile("Permission is hereby granted", Pattern.CASE_INSENSITIVE);
  private static final Map<Pattern, String> LICENSE_PATTERNS =
      Map.ofEntries(
          Map.entry(APACHE_2_PATTERN, "Apache-2.0"),
          Map.entry(AGPL_3_PATTERN, "AGPL-3.0-only"),
          Map.entry(LGPL_3_PATTERN, "LGPL-3.0-only"),
          Map.entry(LGPL_21_PATTERN, "LGPL-2.1-only"),
          Map.entry(GPL_2_PATTERN, "GPL-2.0-only"),
          Map.entry(GPL_3_PATTERN, "GPL-3.0-only"),
          Map.entry(BSD_2_PATTERN, "BSD-2-Clause"),
          Map.entry(BSD_3_PATTERN, "BSD-3-Clause"));

  public enum Compatibility {
    COMPATIBLE,
    INCOMPATIBLE,
    UNKNOWN
  }

  private LicenseUtils() {}

  /**
   * Find LICENSE file path in the same directory as the manifest.
   *
   * @param manifestPath path to the manifest file
   * @return path to LICENSE file or null if not found
   */
  public static Path findLicenseFilePath(Path manifestPath) {
    Path manifestDir = manifestPath.toAbsolutePath().getParent();
    for (String name : LICENSE_FILES) {
      Path filePath = manifestDir.resolve(name);
      if (Files.isRegularFile(filePath)) {
        return filePath;
      }
    }
    return null;
  }

  /**
   * Detect SPDX identifier from license text (first ~500 chars).
   *
   * @param text the license file text content
   * @return SPDX identifier or null
   */
  public static String detectSpdxFromText(String text) {
    String head = text.length() > 500 ? text.substring(0, 500) : text;
    if (MIT_LICENSE_PATTERN.matcher(head).find() && MIT_PERMISSION_PATTERN.matcher(head).find()) {
      return "MIT";
    }
    for (Map.Entry<Pattern, String> entry : LICENSE_PATTERNS.entrySet()) {
      if (entry.getKey().matcher(head).find()) {
        return entry.getValue();
      }
    }
    return null;
  }

  /**
   * Read LICENSE file and detect SPDX identifier.
   *
   * @param manifestPath path to manifest
   * @return SPDX identifier from LICENSE file or null
   */
  public static String readLicenseFile(Path manifestPath) {
    Path licenseFilePath = findLicenseFilePath(manifestPath);
    if (licenseFilePath == null) {
      return null;
    }
    try {
      String content = Files.readString(licenseFilePath, StandardCharsets.UTF_8);
      String detected = detectSpdxFromText(content);
      if (detected != null) {
        return detected;
      }
      String firstLine = content.lines().findFirst().orElse("").trim();
      return firstLine.isEmpty() ? null : firstLine;
    } catch (IOException e) {
      if (debugLoggingIsNeeded()) {
        LOG.warning("Failed reading LICENSE file: " + licenseFilePath);
      }
      return null;
    }
  }

  /**
   * Get project license from manifest or LICENSE file. Returns manifestLicense if provided,
   * otherwise tries LICENSE file.
   *
   * @param manifestLicense license from manifest (or null)
   * @param manifestPath path to manifest
   * @return SPDX identifier or null
   */
  public static String getLicense(String manifestLicense, Path manifestPath) {
    if (manifestLicense != null && !manifestLicense.isBlank()) {
      return manifestLicense;
    }
    return readLicenseFile(manifestPath);
  }

  /**
   * Normalize SPDX identifier for comparison (lowercase, strip common suffixes).
   *
   * @param spdxOrName SPDX identifier or license name
   * @return normalized string
   */
  public static String normalizeSpdx(String spdxOrName) {
    String s = spdxOrName.trim().toLowerCase();
    if (s.endsWith(" license")) {
      return s.substring(0, s.length() - 8);
    }
    return s;
  }

  /**
   * Check if a dependency's license is compatible with the project license based on backend
   * categories.
   *
   * @param projectCategory backend category for project license
   * @param dependencyCategory backend category for dependency license
   * @return compatibility result
   */
  public static Compatibility getCompatibility(
      LicenseCategory projectCategory, LicenseCategory dependencyCategory) {
    if (projectCategory == null || dependencyCategory == null) {
      return Compatibility.UNKNOWN;
    }
    if (projectCategory == LicenseCategory.UNKNOWN
        || dependencyCategory == LicenseCategory.UNKNOWN) {
      return Compatibility.UNKNOWN;
    }
    int projLevel = restrictiveness(projectCategory);
    int depLevel = restrictiveness(dependencyCategory);

    if (projLevel < 0 || depLevel < 0) {
      return Compatibility.UNKNOWN;
    }
    return depLevel > projLevel ? Compatibility.INCOMPATIBLE : Compatibility.COMPATIBLE;
  }

  /**
   * Extract category from a license details JSON response.
   *
   * @param licenseDetails JSON node from getLicenseDetails
   * @return LicenseCategory or null
   */
  public static LicenseCategory extractCategory(JsonNode licenseDetails) {
    if (licenseDetails == null) {
      return null;
    }
    JsonNode categoryNode = licenseDetails.get("category");
    if (categoryNode != null && !categoryNode.isNull()) {
      try {
        return LicenseCategory.fromValue(categoryNode.asText());
      } catch (IllegalArgumentException e) {
        return null;
      }
    }
    return null;
  }

  private static int restrictiveness(LicenseCategory category) {
    return switch (category) {
      case PERMISSIVE -> 1;
      case WEAK_COPYLEFT -> 2;
      case STRONG_COPYLEFT -> 3;
      default -> -1;
    };
  }

  /**
   * Build license map from an analysis report that already includes license data. Extracts
   * dependency licenses from the report's licenses array.
   *
   * @param analysisReport the analysis report from the backend
   * @param purls optional collection of purls to restrict to (empty means all)
   * @return map of purl to DependencyLicenseInfo
   */
  public static Map<String, DependencyLicenseInfo> licensesFromReport(
      AnalysisReport analysisReport, Collection<String> purls) {
    Map<String, DependencyLicenseInfo> result = new HashMap<>();
    if (analysisReport == null || analysisReport.getLicenses() == null) {
      return result;
    }

    Set<String> normalizedPurls =
        (purls != null && !purls.isEmpty())
            ? purls.stream().map(LicenseUtils::normalizePurlString).collect(Collectors.toSet())
            : null;

    for (LicenseProviderResult providerResult : analysisReport.getLicenses()) {
      Map<String, PackageLicenseResult> packages = providerResult.getPackages();
      if (packages == null) {
        continue;
      }

      for (Map.Entry<String, PackageLicenseResult> entry : packages.entrySet()) {
        String purl = entry.getKey();
        String normalizedPurl = normalizePurlString(purl);
        if (normalizedPurls != null && !normalizedPurls.contains(normalizedPurl)) {
          continue;
        }

        PackageLicenseResult pkgLicense = entry.getValue();
        LicenseInfo concluded = pkgLicense.getConcluded();
        List<LicenseIdentifier> licenses = new ArrayList<>();
        LicenseCategory category = null;

        if (concluded != null) {
          if (concluded.getIdentifiers() != null) {
            licenses.addAll(concluded.getIdentifiers());
          }
          category = concluded.getCategory();
        }

        result.put(normalizedPurl, new DependencyLicenseInfo(licenses, category));
      }

      if (!result.isEmpty()) {
        break;
      }
    }

    return result;
  }

  /**
   * Canonicalize a PURL string by stripping qualifiers and subpath. Uses {@link PackageURL} for
   * proper parsing. For example, {@code pkg:maven/log4j/log4j@1.2.17?scope=compile} becomes {@code
   * pkg:maven/log4j/log4j@1.2.17}.
   */
  static String normalizePurlString(String purl) {
    try {
      PackageURL normalizedPurl = new PackageURL(purl);
      return new PackageURL(
              normalizedPurl.getType(),
              normalizedPurl.getNamespace(),
              normalizedPurl.getName(),
              normalizedPurl.getVersion(),
              null,
              null)
          .canonicalize();
    } catch (MalformedPackageURLException e) {
      LOG.warning("Unable to parse PackageURL " + purl);
      return purl;
    }
  }

  public record DependencyLicenseInfo(List<LicenseIdentifier> licenses, LicenseCategory category) {}
}
