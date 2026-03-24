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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.api.v5.LicenseIdentifier;
import io.github.guacsec.trustifyda.impl.ExhortApi;
import io.github.guacsec.trustifyda.license.LicenseUtils.Compatibility;
import io.github.guacsec.trustifyda.license.LicenseUtils.DependencyLicenseInfo;
import io.github.guacsec.trustifyda.license.ProjectLicense.ProjectLicenseInfo;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

/**
 * Orchestrates the full license check: resolves the project license, fetches license details from
 * the backend, extracts dependency licenses from the analysis report, and computes
 * incompatibilities.
 */
public final class LicenseCheck {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static final Logger LOG = LoggersFactory.getLogger(LicenseCheck.class.getName());

  private LicenseCheck() {}

  /**
   * Run full license check after a component analysis.
   *
   * @param api the ExhortApi instance (provides HTTP client, endpoint, and auth headers)
   * @param manifestPath path to the project manifest
   * @param sbomJson the CycloneDX SBOM JSON string that was sent for analysis
   * @param analysisReport the analysis report returned by the backend
   * @return a CompletableFuture with the license summary
   */
  public static CompletableFuture<LicenseSummary> runLicenseCheck(
      ExhortApi api,
      Provider provider,
      Path manifestPath,
      String sbomJson,
      AnalysisReport analysisReport) {

    ProjectLicenseInfo projectLicense = ProjectLicense.getProjectLicense(provider, manifestPath);

    Path licenseFilePath = LicenseUtils.findLicenseFilePath(manifestPath);
    CompletableFuture<String> backendFileIdFuture;
    if (licenseFilePath != null) {
      backendFileIdFuture =
          api.identifyLicense(licenseFilePath)
              .exceptionally(
                  ex -> {
                    // Fall back to local detection
                    return null;
                  });
    } else {
      backendFileIdFuture = CompletableFuture.completedFuture(null);
    }

    return backendFileIdFuture.thenCompose(
        backendFileId -> {
          String manifestSpdx = projectLicense.fromManifest();
          String fileSpdx = backendFileId != null ? backendFileId : projectLicense.fromFile();
          boolean mismatch =
              manifestSpdx != null
                  && fileSpdx != null
                  && !LicenseUtils.normalizeSpdx(manifestSpdx)
                      .equals(LicenseUtils.normalizeSpdx(fileSpdx));

          CompletableFuture<JsonNode> manifestDetailsFuture =
              manifestSpdx != null
                  ? api.getLicenseDetails(manifestSpdx)
                  : CompletableFuture.completedFuture(null);

          CompletableFuture<JsonNode> fileDetailsFuture;
          if (fileSpdx != null
              && (manifestSpdx == null
                  || !LicenseUtils.normalizeSpdx(manifestSpdx)
                      .equals(LicenseUtils.normalizeSpdx(fileSpdx)))) {
            fileDetailsFuture = api.getLicenseDetails(fileSpdx);
          } else if (fileSpdx != null) {
            // Same license — reuse the manifest details future
            fileDetailsFuture = manifestDetailsFuture;
          } else {
            fileDetailsFuture = CompletableFuture.completedFuture(null);
          }

          return manifestDetailsFuture.thenCombine(
              fileDetailsFuture,
              (manifestDetails, fileDetails) -> {
                ProjectLicenseSummary projectLicenseSummary =
                    new ProjectLicenseSummary(manifestDetails, fileDetails, mismatch);

                List<String> purls =
                    extractPurls(sbomJson).stream().map(LicenseUtils::normalizePurlString).toList();
                if (purls.isEmpty()) {
                  return new LicenseSummary(projectLicenseSummary, Collections.emptyList(), null);
                }

                Map<String, DependencyLicenseInfo> licenseByPurl =
                    LicenseUtils.licensesFromReport(analysisReport, purls);

                if (licenseByPurl.isEmpty()) {
                  return new LicenseSummary(
                      projectLicenseSummary,
                      Collections.emptyList(),
                      "No license data available in analysis report");
                }

                LicenseCategory manifestCategory = LicenseUtils.extractCategory(manifestDetails);
                LicenseCategory fileCategory = LicenseUtils.extractCategory(fileDetails);
                LicenseCategory projectCategory =
                    manifestCategory != null ? manifestCategory : fileCategory;
                List<IncompatibleDependency> incompatible = new ArrayList<>();

                for (String purl : purls) {
                  DependencyLicenseInfo entry = licenseByPurl.get(purl);
                  if (entry == null) {
                    continue;
                  }
                  Compatibility status =
                      LicenseUtils.getCompatibility(projectCategory, entry.category());
                  if (status == Compatibility.INCOMPATIBLE) {
                    incompatible.add(
                        new IncompatibleDependency(
                            purl,
                            entry.licenses(),
                            entry.category(),
                            "Dependency license(s) are incompatible with the project license."));
                  }
                }

                return new LicenseSummary(projectLicenseSummary, incompatible, null);
              });
        });
  }

  private static List<String> extractPurls(String sbomJson) {
    try {
      JsonNode sbom = MAPPER.readTree(sbomJson);

      // Get root ref to exclude it
      String rootRef = null;
      JsonNode metadata = sbom.get("metadata");
      if (metadata != null) {
        JsonNode component = metadata.get("component");
        if (component != null) {
          if (component.has("bom-ref")) {
            rootRef = component.get("bom-ref").asText(null);
          } else if (component.has("purl")) {
            rootRef = component.get("purl").asText(null);
          }
        }
      }

      String normalizedRootRef = rootRef != null ? LicenseUtils.normalizePurlString(rootRef) : null;

      List<String> purls = new ArrayList<>();
      JsonNode components = sbom.get("components");
      if (components != null && components.isArray()) {
        for (JsonNode comp : components) {
          String purl = comp.has("purl") ? comp.get("purl").asText(null) : null;
          if (purl == null) {
            purl = comp.has("bom-ref") ? comp.get("bom-ref").asText(null) : null;
          }
          if (purl != null
              && (normalizedRootRef == null
                  || !LicenseUtils.normalizePurlString(purl).equals(normalizedRootRef))) {
            purls.add(purl);
          }
        }
      }
      return purls;
    } catch (IOException e) {
      LOG.warning(String.format("Failed to extract PURLs from SBOM: %s", e.getMessage()));
      return Collections.emptyList();
    }
  }

  public record LicenseSummary(
      ProjectLicenseSummary projectLicense,
      List<IncompatibleDependency> incompatibleDependencies,
      String error) {}

  public record ProjectLicenseSummary(JsonNode manifest, JsonNode file, boolean mismatch) {}

  public record IncompatibleDependency(
      String purl, List<LicenseIdentifier> licenses, LicenseCategory category, String reason) {}
}
