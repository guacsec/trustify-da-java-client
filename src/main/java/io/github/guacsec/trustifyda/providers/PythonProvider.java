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
package io.github.guacsec.trustifyda.providers;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.license.LicenseUtils;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.utils.Environment;
import io.github.guacsec.trustifyda.utils.IgnorePatternDetector;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Abstract base class for Python providers. Encapsulates shared Python infrastructure including
 * PURL construction, ignore-pattern handling, and root component defaults.
 */
public abstract class PythonProvider extends Provider {

  static final String DEFAULT_PIP_ROOT_COMPONENT_NAME = "default-pip-root";
  static final String DEFAULT_PIP_ROOT_COMPONENT_VERSION = "0.0.0";

  protected PythonProvider(Path manifest) {
    super(Ecosystem.Type.PYTHON, manifest);
  }

  @Override
  public String readLicenseFromManifest() {
    return LicenseUtils.readLicenseFile(manifestPath);
  }

  protected String getRootComponentName() {
    return DEFAULT_PIP_ROOT_COMPONENT_NAME;
  }

  protected String getRootComponentVersion() {
    return DEFAULT_PIP_ROOT_COMPONENT_VERSION;
  }

  /** Parse ignored dependencies from the raw manifest content. */
  protected abstract Set<PackageURL> getIgnoredDependencies(String manifestContent);

  protected void handleIgnoredDependencies(String manifestContent, Sbom sbom) {
    Set<PackageURL> ignoredDeps = getIgnoredDependencies(manifestContent);
    Set<String> ignoredDepsVersions =
        ignoredDeps.stream()
            .filter(dep -> !dep.getVersion().trim().equals("*"))
            .map(PackageURL::getCoordinates)
            .collect(Collectors.toSet());
    Set<String> ignoredDepsNoVersions =
        ignoredDeps.stream()
            .filter(dep -> dep.getVersion().trim().equals("*"))
            .map(PackageURL::getName)
            .collect(Collectors.toSet());

    sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.NAME);
    sbom.filterIgnoredDeps(ignoredDepsNoVersions);
    boolean matchManifestVersions = Environment.getBoolean(PROP_MATCH_MANIFEST_VERSIONS, true);
    if (matchManifestVersions) {
      sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.PURL);
      sbom.filterIgnoredDeps(ignoredDepsVersions);
    } else {
      Set<String> deps =
          ignoredDepsVersions.stream()
              .map(
                  purlString -> {
                    try {
                      return new PackageURL(purlString).getName();
                    } catch (MalformedPackageURLException e) {
                      throw new RuntimeException(e);
                    }
                  })
              .collect(Collectors.toSet());
      sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.NAME);
      sbom.filterIgnoredDeps(deps);
    }
  }

  protected boolean containsIgnorePattern(String line) {
    return line.contains("#" + IgnorePatternDetector.IGNORE_PATTERN)
        || line.contains("# " + IgnorePatternDetector.IGNORE_PATTERN)
        || line.contains("#" + IgnorePatternDetector.LEGACY_IGNORE_PATTERN)
        || line.contains("# " + IgnorePatternDetector.LEGACY_IGNORE_PATTERN);
  }

  protected PackageURL toPurl(String name, String version) {
    try {
      return new PackageURL(Ecosystem.Type.PYTHON.getType(), null, name, version, null, null);
    } catch (MalformedPackageURLException e) {
      throw new RuntimeException(e);
    }
  }
}
