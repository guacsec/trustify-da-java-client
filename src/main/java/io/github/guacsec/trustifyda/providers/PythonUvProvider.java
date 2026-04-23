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

import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.license.LicenseUtils;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.sbom.SbomFactory;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.Environment;
import io.github.guacsec.trustifyda.utils.PyprojectTomlUtils;
import io.github.guacsec.trustifyda.utils.PythonControllerBase;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.tomlj.TomlParseResult;

/**
 * Provider for Python projects using {@code pyproject.toml} with the <a
 * href="https://docs.astral.sh/uv/">uv</a> package manager.
 *
 * <p>Dependency resolution is performed via {@code uv export --format requirements.txt --frozen
 * --no-hashes --no-dev --no-emit-project}, which produces a requirements.txt with {@code # via}
 * comments encoding the full dependency graph. The provider is selected by {@link
 * PythonProviderFactory} when {@code uv.lock} is present alongside the manifest.
 */
public final class PythonUvProvider extends PythonProvider {

  private static final Logger log = LoggersFactory.getLogger(PythonUvProvider.class.getName());

  public static final String LOCK_FILE = "uv.lock";
  static final String PROP_TRUSTIFY_DA_UV_EXPORT = "TRUSTIFY_DA_UV_EXPORT";

  private final String uvExecutable;
  private Set<String> collectedIgnoredDeps;
  private TomlParseResult cachedToml;

  public PythonUvProvider(Path manifest) {
    super(manifest);
    this.uvExecutable = Operations.getExecutable("uv", "--version");
  }

  @Override
  public void validateLockFile(Path lockFileDir) {
    // Check manifest directory first, then walk up to workspace root
    if (Files.isRegularFile(lockFileDir.resolve(LOCK_FILE))) {
      return;
    }
    Path parentDir = PythonProviderFactory.findLockFileDirInParents(lockFileDir);
    if (parentDir != null && Files.isRegularFile(parentDir.resolve(LOCK_FILE))) {
      return;
    }
    throw new IllegalStateException(
        "uv.lock does not exist. Ensure the project is managed by uv"
            + " and run 'uv lock' to generate it.");
  }

  @Override
  public Content provideStack() throws IOException {
    rejectPoetryDependencies();
    collectIgnoredDeps();
    Path manifestDir = manifestPath.toAbsolutePath().getParent();
    String exportOutput = getUvExportOutput(manifestDir);
    UvDependencyData data = parseUvExport(exportOutput);

    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    sbom.addRoot(
        toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());

    for (String directKey : data.directDeps()) {
      UvPackage pkg = data.graph().get(directKey);
      if (pkg != null) {
        addDependencyTree(sbom.getRoot(), pkg, data.graph(), sbom, new HashSet<>());
      }
    }

    String manifestContent = Files.readString(manifestPath);
    handleIgnoredDependencies(manifestContent, sbom);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideComponent() throws IOException {
    rejectPoetryDependencies();
    collectIgnoredDeps();
    Path manifestDir = manifestPath.toAbsolutePath().getParent();
    String exportOutput = getUvExportOutput(manifestDir);
    UvDependencyData data = parseUvExport(exportOutput);

    Sbom sbom = SbomFactory.newInstance();
    sbom.addRoot(
        toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());

    for (String key : data.directDeps()) {
      UvPackage pkg = data.graph().get(key);
      if (pkg != null) {
        sbom.addDependency(sbom.getRoot(), toPurl(pkg.name(), pkg.version()), null);
      }
    }

    String manifestContent = Files.readString(manifestPath);
    handleIgnoredDependencies(manifestContent, sbom);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private void addDependencyTree(
      PackageURL source,
      UvPackage pkg,
      Map<String, UvPackage> graph,
      Sbom sbom,
      Set<String> visited) {
    PackageURL packageURL = toPurl(pkg.name(), pkg.version());
    sbom.addDependency(source, packageURL, null);

    String key = PyprojectTomlUtils.canonicalize(pkg.name());
    if (!visited.add(key)) {
      return;
    }

    for (String childKey : pkg.children()) {
      UvPackage child = graph.get(childKey);
      if (child != null) {
        addDependencyTree(packageURL, child, graph, sbom, visited);
      }
    }
  }

  /**
   * Parses the output of {@code uv export --format requirements.txt} into a dependency graph.
   *
   * <p>Each package line has the form {@code name==version} optionally followed by environment
   * markers. Dependency relationships are encoded in {@code # via} comments that follow each
   * package. A package whose {@code # via} parent is the project name is a direct dependency.
   */
  UvDependencyData parseUvExport(String exportOutput) throws IOException {
    String projectName = PyprojectTomlUtils.canonicalize(getRootComponentName());
    Map<String, UvPackage> packages = new HashMap<>();
    List<String> directDeps = new ArrayList<>();
    List<String[]> parentChildPairs = new ArrayList<>();

    String currentKey = null;
    boolean inViaBlock = false;

    for (String line : exportOutput.split("\\r?\\n")) {
      String trimmed = line.trim();

      if (trimmed.isEmpty()) {
        inViaBlock = false;
        continue;
      }

      // Skip top-level comments (header lines)
      if (line.startsWith("#")) {
        continue;
      }

      // Skip editable installs (workspace members)
      if (line.startsWith("-e ")) {
        currentKey = null;
        inViaBlock = false;
        continue;
      }

      // Package line: name==version [; env-marker]
      if (!line.startsWith(" ") && trimmed.contains("==")) {
        inViaBlock = false;
        String spec = trimmed.split(";")[0].trim();
        String[] parts = spec.split("==", 2);
        String name = parts[0].split("\\[")[0].trim(); // strip extras like [bar]
        String version = parts[1].trim();
        currentKey = PyprojectTomlUtils.canonicalize(name);
        packages.put(currentKey, new UvPackage(name, version, new ArrayList<>()));
        continue;
      }

      // Indented "# via ..." line
      if (trimmed.startsWith("# via") && currentKey != null) {
        inViaBlock = true;
        String rest = trimmed.substring("# via".length()).trim();
        if (!rest.isEmpty()) {
          recordViaParent(rest, currentKey, projectName, directDeps, parentChildPairs);
        }
        continue;
      }

      // Multi-line via continuation: "#   parent-name"
      if (inViaBlock && trimmed.startsWith("#") && currentKey != null) {
        String parent = trimmed.substring(1).trim();
        if (!parent.isEmpty()) {
          recordViaParent(parent, currentKey, projectName, directDeps, parentChildPairs);
        }
      }
    }

    // Resolve parent→child relationships
    for (String[] pair : parentChildPairs) {
      UvPackage parent = packages.get(pair[0]);
      if (parent != null && !parent.children().contains(pair[1])) {
        parent.children().add(pair[1]);
      }
    }

    return new UvDependencyData(directDeps, packages);
  }

  private static void recordViaParent(
      String parentName,
      String childKey,
      String projectName,
      List<String> directDeps,
      List<String[]> parentChildPairs) {
    String parentKey = PyprojectTomlUtils.canonicalize(parentName);
    if (parentKey.equals(projectName)) {
      if (!directDeps.contains(childKey)) {
        directDeps.add(childKey);
      }
    } else {
      parentChildPairs.add(new String[] {parentKey, childKey});
    }
  }

  String getUvExportOutput(Path manifestDir) {
    String envValue = Environment.get(PROP_TRUSTIFY_DA_UV_EXPORT);
    if (envValue != null && !envValue.isBlank()) {
      return envValue;
    }

    String[] cmd = {
      uvExecutable,
      "export",
      "--format",
      "requirements.txt",
      "--frozen",
      "--no-hashes",
      "--no-dev",
      "--no-emit-project"
    };
    Operations.ProcessExecOutput result =
        Operations.runProcessGetFullOutput(manifestDir, cmd, null);
    if (result.getExitCode() != 0) {
      throw new RuntimeException(
          String.format(
              "uv export command failed with exit code %d: %s",
              result.getExitCode(), result.getError()));
    }
    return result.getOutput();
  }

  // --- TOML parsing (shared with PythonPyprojectProvider) ---

  private TomlParseResult getToml() throws IOException {
    if (cachedToml == null) {
      cachedToml = PyprojectTomlUtils.parseToml(manifestPath);
    }
    return cachedToml;
  }

  @Override
  protected String getRootComponentName() {
    try {
      String name = PyprojectTomlUtils.getProjectName(getToml());
      if (name != null) {
        return name;
      }
    } catch (IOException e) {
      log.fine("Failed to parse pyproject.toml for root component name: " + e.getMessage());
    }
    return super.getRootComponentName();
  }

  @Override
  protected String getRootComponentVersion() {
    try {
      String version = PyprojectTomlUtils.getProjectVersion(getToml());
      if (version != null) {
        return version;
      }
    } catch (IOException e) {
      log.fine("Failed to parse pyproject.toml for root component version: " + e.getMessage());
    }
    return super.getRootComponentVersion();
  }

  @Override
  public String readLicenseFromManifest() {
    try {
      String license = PyprojectTomlUtils.getLicense(getToml());
      if (license != null) {
        return license;
      }
    } catch (IOException e) {
      log.fine("Failed to parse pyproject.toml for license: " + e.getMessage());
    }
    return LicenseUtils.readLicenseFile(manifestPath);
  }

  @Override
  protected Set<PackageURL> getIgnoredDependencies(String manifestContent) {
    if (collectedIgnoredDeps == null) {
      return Set.of();
    }
    return collectedIgnoredDeps.stream()
        .map(
            dep -> {
              String name = PythonControllerBase.getDependencyName(dep);
              return toPurl(name, "*");
            })
        .collect(Collectors.toSet());
  }

  private void rejectPoetryDependencies() throws IOException {
    if (PyprojectTomlUtils.hasPoetryDependencies(getToml())) {
      throw new IllegalStateException(
          "Poetry dependencies in pyproject.toml are not supported."
              + " Please use PEP 621 [project.dependencies] format instead.");
    }
  }

  private void collectIgnoredDeps() throws IOException {
    collectedIgnoredDeps = PyprojectTomlUtils.collectIgnoredDeps(manifestPath, getToml());
  }

  record UvPackage(String name, String version, List<String> children) {}

  record UvDependencyData(List<String> directDeps, Map<String, UvPackage> graph) {}
}
