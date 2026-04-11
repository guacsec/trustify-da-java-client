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

import static io.github.guacsec.trustifyda.impl.ExhortApi.debugLoggingIsNeeded;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.license.LicenseUtils;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.sbom.SbomFactory;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.Environment;
import io.github.guacsec.trustifyda.utils.IgnorePatternDetector;
import io.github.guacsec.trustifyda.utils.PythonControllerBase;
import io.github.guacsec.trustifyda.utils.PythonControllerRealEnv;
import io.github.guacsec.trustifyda.utils.PythonControllerVirtualEnv;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Abstract base class for Python providers. Encapsulates shared Python infrastructure including
 * controller resolution, executable discovery, SBOM construction, and ignore-pattern handling.
 */
public abstract class PythonProvider extends Provider {

  private static final Logger log = LoggersFactory.getLogger(PythonProvider.class.getName());
  static final String DEFAULT_PIP_ROOT_COMPONENT_NAME = "default-pip-root";
  static final String DEFAULT_PIP_ROOT_COMPONENT_VERSION = "0.0.0";

  private PythonControllerBase pythonController;

  protected PythonProvider(Path manifest) {
    super(Ecosystem.Type.PYTHON, manifest);
  }

  public void setPythonController(PythonControllerBase pythonController) {
    this.pythonController = pythonController;
  }

  @Override
  public String readLicenseFromManifest() {
    return LicenseUtils.readLicenseFile(manifest);
  }

  protected String getRootComponentName() {
    return DEFAULT_PIP_ROOT_COMPONENT_NAME;
  }

  protected String getRootComponentVersion() {
    return DEFAULT_PIP_ROOT_COMPONENT_VERSION;
  }

  /**
   * Returns the path to a requirements-format file that the {@link PythonControllerBase} can
   * consume. For requirements.txt this is the manifest itself; for pyproject.toml a temporary file
   * is generated.
   */
  protected abstract Path getRequirementsPath() throws IOException;

  /** Clean up any temporary files created by {@link #getRequirementsPath()}. */
  protected abstract void cleanupRequirementsPath(Path requirementsPath) throws IOException;

  /** Parse ignored dependencies from the raw manifest content. */
  protected abstract Set<PackageURL> getIgnoredDependencies(String manifestContent);

  @Override
  public Content provideStack() throws IOException {
    Path requirementsPath = getRequirementsPath();
    try {
      PythonControllerBase controller = getPythonController();
      List<Map<String, Object>> dependencies =
          controller.getDependencies(requirementsPath.toString(), true);
      printDependenciesTree(dependencies);
      Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
      sbom.addRoot(
          toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());
      for (Map<String, Object> component : dependencies) {
        addAllDependencies(sbom.getRoot(), component, sbom);
      }
      String manifestContent = Files.readString(manifest);
      handleIgnoredDependencies(manifestContent, sbom);
      return new Content(
          sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
    } finally {
      try {
        cleanupRequirementsPath(requirementsPath);
      } catch (IOException e) {
        log.warning("Failed to clean up temporary requirements file: " + e.getMessage());
      }
    }
  }

  @Override
  public Content provideComponent() throws IOException {
    Path requirementsPath = getRequirementsPath();
    try {
      PythonControllerBase controller = getPythonController();
      List<Map<String, Object>> dependencies =
          controller.getDependencies(requirementsPath.toString(), false);
      printDependenciesTree(dependencies);
      Sbom sbom = SbomFactory.newInstance();
      sbom.addRoot(
          toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());
      dependencies.forEach(
          (component) ->
              sbom.addDependency(
                  sbom.getRoot(),
                  toPurl((String) component.get("name"), (String) component.get("version")),
                  null));
      String manifestContent = Files.readString(manifest);
      handleIgnoredDependencies(manifestContent, sbom);
      return new Content(
          sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
    } finally {
      try {
        cleanupRequirementsPath(requirementsPath);
      } catch (IOException e) {
        log.warning("Failed to clean up temporary requirements file: " + e.getMessage());
      }
    }
  }

  @SuppressWarnings("unchecked")
  private void addAllDependencies(PackageURL source, Map<String, Object> component, Sbom sbom) {
    PackageURL packageURL =
        toPurl((String) component.get("name"), (String) component.get("version"));
    sbom.addDependency(source, packageURL, null);

    List<Map<String, Object>> directDeps =
        (List<Map<String, Object>>) component.get("dependencies");
    if (directDeps != null) {
      for (Map<String, Object> dep : directDeps) {
        addAllDependencies(packageURL, dep, sbom);
      }
    }
  }

  private void printDependenciesTree(List<Map<String, Object>> dependencies)
      throws JsonProcessingException {
    if (debugLoggingIsNeeded()) {
      String pythonControllerTree =
          objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dependencies);
      log.info(
          String.format(
              "Python Generated Dependency Tree in Json Format: %s %s %s",
              System.lineSeparator(), pythonControllerTree, System.lineSeparator()));
    }
  }

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

  protected PythonControllerBase getPythonController() {
    String pythonPipBinaries;
    boolean useVirtualPythonEnv;
    if (!Environment.get(PythonControllerBase.PROP_TRUSTIFY_DA_PIP_SHOW, "").trim().isEmpty()
        && !Environment.get(PythonControllerBase.PROP_TRUSTIFY_DA_PIP_FREEZE, "")
            .trim()
            .isEmpty()) {
      pythonPipBinaries = "python;;pip";
      useVirtualPythonEnv = false;
    } else {
      pythonPipBinaries = getExecutable("python", "--version");
      useVirtualPythonEnv =
          Environment.getBoolean(PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV, false);
    }

    String[] parts = pythonPipBinaries.split(";;");
    var python = parts[0];
    var pip = parts[1];
    PythonControllerBase controller;
    if (this.pythonController == null) {
      if (useVirtualPythonEnv) {
        controller = new PythonControllerVirtualEnv(python);
      } else {
        controller = new PythonControllerRealEnv(python, pip);
      }
    } else {
      controller = this.pythonController;
    }
    return controller;
  }

  private String getExecutable(String command, String args) {
    String python = Operations.getCustomPathOrElse("python3");
    String pip = Operations.getCustomPathOrElse("pip3");
    try {
      Operations.runProcess(python, args);
      Operations.runProcess(pip, args);
    } catch (Exception e) {
      python = Operations.getCustomPathOrElse("python");
      pip = Operations.getCustomPathOrElse("pip");
      try {
        Process process = new ProcessBuilder(command, args).redirectErrorStream(true).start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
          throw new IOException(
              "Python executable found, but it exited with error code " + exitCode);
        }
      } catch (IOException | InterruptedException ex) {
        throw new RuntimeException(
            String.format(
                "Unable to find or run Python executable '%s'. Please ensure Python is installed"
                    + " and available in your PATH.",
                command),
            ex);
      }

      try {
        Process process = new ProcessBuilder("pip", args).redirectErrorStream(true).start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
          throw new IOException("Pip executable found, but it exited with error code " + exitCode);
        }
      } catch (IOException | InterruptedException ex) {
        throw new RuntimeException(
            String.format(
                "Unable to find or run Pip executable '%s'. Please ensure Pip is installed and"
                    + " available in your PATH.",
                command),
            ex);
      }
    }
    return String.format("%s;;%s", python, pip);
  }
}
