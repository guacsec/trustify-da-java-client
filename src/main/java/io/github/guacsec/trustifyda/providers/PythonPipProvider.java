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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public final class PythonPipProvider extends Provider {

  private static final Logger log = LoggersFactory.getLogger(PythonPipProvider.class.getName());
  private static final String DEFAULT_PIP_ROOT_COMPONENT_NAME = "default-pip-root";
  private static final String DEFAULT_PIP_ROOT_COMPONENT_VERSION = "0.0.0";

  public void setPythonController(PythonControllerBase pythonController) {
    this.pythonController = pythonController;
  }

  private PythonControllerBase pythonController;

  public PythonPipProvider(Path manifest) {
    super(Ecosystem.Type.PYTHON, manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    PythonControllerBase pythonController = getPythonController();
    List<Map<String, Object>> dependencies =
        pythonController.getDependencies(manifest.toString(), true);
    printDependenciesTree(dependencies);
    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    sbom.addRoot(toPurl(DEFAULT_PIP_ROOT_COMPONENT_NAME, DEFAULT_PIP_ROOT_COMPONENT_VERSION));
    for (Map<String, Object> component : dependencies) {
      addAllDependencies(sbom.getRoot(), component, sbom);
    }
    byte[] requirementsFile = Files.readAllBytes(manifest);
    handleIgnoredDependencies(new String(requirementsFile), sbom);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

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

  @Override
  public Content provideComponent() throws IOException {
    PythonControllerBase pythonController = getPythonController();
    List<Map<String, Object>> dependencies =
        pythonController.getDependencies(manifest.toString(), false);
    printDependenciesTree(dependencies);
    Sbom sbom = SbomFactory.newInstance();
    sbom.addRoot(toPurl(DEFAULT_PIP_ROOT_COMPONENT_NAME, DEFAULT_PIP_ROOT_COMPONENT_VERSION));
    dependencies.forEach(
        (component) ->
            sbom.addDependency(
                sbom.getRoot(),
                toPurl((String) component.get("name"), (String) component.get("version")),
                null));

    var manifestContent = Files.readString(manifest);
    handleIgnoredDependencies(manifestContent, sbom);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
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

  private void handleIgnoredDependencies(String manifestContent, Sbom sbom) {
    Set<PackageURL> ignoredDeps = getIgnoredDependencies(manifestContent);
    Set<String> ignoredDepsVersions =
        ignoredDeps.stream()
            .filter(dep -> !dep.getVersion().trim().equals("*"))
            .map(PackageURL::getCoordinates)
            .collect(Collectors.toSet());
    Set<String> ignoredDepsNoVersions =
        ignoredDeps.stream()
            .filter(dep -> dep.getVersion().trim().equals("*"))
            .map(PackageURL::getCoordinates)
            .collect(Collectors.toSet());

    // filter out by name only from sbom all exhortignore dependencies that their version will be
    // resolved by pip.
    sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.NAME);
    sbom.filterIgnoredDeps(ignoredDepsNoVersions);
    boolean matchManifestVersions = Environment.getBoolean(PROP_MATCH_MANIFEST_VERSIONS, true);
    // filter out by purl from sbom all exhortignore dependencies that their version hardcoded in
    // requirements.txt -
    // in case all versions in manifest matching installed versions of packages in environment.
    if (matchManifestVersions) {
      sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.PURL);
      sbom.filterIgnoredDeps(ignoredDepsVersions);
    } else {
      // in case version mismatch is possible (MATCH_MANIFEST_VERSIONS=false) , need to parse the
      // name of package
      // from the purl, and remove the package name from sbom according to name only
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

  /**
   * Checks if a text line contains a Python pip ignore pattern. Handles both '#exhortignore' and
   * '#trustify-da-ignore' with optional spacing.
   *
   * @param line the line to check
   * @return true if the line contains a Python pip ignore pattern
   */
  private boolean containsPythonIgnorePattern(String line) {
    return line.contains("#" + IgnorePatternDetector.IGNORE_PATTERN)
        || line.contains("# " + IgnorePatternDetector.IGNORE_PATTERN)
        || line.contains("#" + IgnorePatternDetector.LEGACY_IGNORE_PATTERN)
        || line.contains("# " + IgnorePatternDetector.LEGACY_IGNORE_PATTERN);
  }

  private Set<PackageURL> getIgnoredDependencies(String requirementsDeps) {

    String[] requirementsLines = requirementsDeps.split(System.lineSeparator());
    Set<PackageURL> collected =
        Arrays.stream(requirementsLines)
            .filter(this::containsPythonIgnorePattern)
            .map(PythonPipProvider::extractDepFull)
            .map(this::splitToNameVersion)
            .map(dep -> toPurl(dep[0], dep[1]))
            //      .map(packageURL -> packageURL.getCoordinates())
            .collect(Collectors.toSet());

    return collected;
  }

  private String[] splitToNameVersion(String nameVersion) {
    String[] result;
    if (nameVersion.matches(
        "[a-zA-Z0-9-_()]+={2}[0-9]{1,4}[.][0-9]{1,4}(([.][0-9]{1,4})|([.][a-zA-Z0-9]+)|([a-zA-Z0-9]+)|([.][a-zA-Z0-9]+[.][a-z-A-Z0-9]+))?")) {
      result = nameVersion.split("==");
    } else {
      String dependencyName = PythonControllerBase.getDependencyName(nameVersion);
      result = new String[] {dependencyName, "*"};
    }
    return result;
  }

  private static String extractDepFull(String requirementLine) {
    return requirementLine.substring(0, requirementLine.indexOf("#")).trim();
  }

  private PackageURL toPurl(String name, String version) {

    try {
      return new PackageURL(Ecosystem.Type.PYTHON.getType(), null, name, version, null, null);
    } catch (MalformedPackageURLException e) {
      throw new RuntimeException(e);
    }
  }

  private PythonControllerBase getPythonController() {
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
    PythonControllerBase pythonController;
    if (this.pythonController == null) {
      if (useVirtualPythonEnv) {
        pythonController = new PythonControllerVirtualEnv(python);
      } else {
        pythonController = new PythonControllerRealEnv(python, pip);
      }
    } else {
      pythonController = this.pythonController;
    }
    return pythonController;
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
