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

import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;

/**
 * Provider for Python projects using {@code pyproject.toml} with the <a
 * href="https://docs.astral.sh/uv/">uv</a> package manager.
 *
 * <p>Dependency resolution is performed via {@code uv pip list --format=json} and {@code uv pip
 * show}, which are pip-compatible output formats. The provider is selected by {@link
 * PythonProviderFactory} when {@code uv.lock} is present alongside the manifest.
 */
public final class PythonUvProvider extends PythonProvider {

  private static final Logger log = LoggersFactory.getLogger(PythonUvProvider.class.getName());

  public static final String LOCK_FILE = "uv.lock";
  static final String PROP_TRUSTIFY_DA_UV_PIP_LIST = "TRUSTIFY_DA_UV_PIP_LIST";
  static final String PROP_TRUSTIFY_DA_UV_PIP_SHOW = "TRUSTIFY_DA_UV_PIP_SHOW";

  private final String uvExecutable;
  private Set<String> collectedIgnoredDeps;
  private TomlParseResult cachedToml;

  public PythonUvProvider(Path manifest) {
    super(manifest);
    this.uvExecutable = Operations.getExecutable("uv", "--version");
  }

  @Override
  public void validateLockFile(Path lockFileDir) {
    if (!Files.isRegularFile(lockFileDir.resolve(LOCK_FILE))) {
      throw new IllegalStateException(
          "uv.lock does not exist. Ensure the project is managed by uv"
              + " and run 'uv lock' to generate it.");
    }
  }

  @Override
  public Content provideStack() throws IOException {
    rejectPoetryDependencies();
    collectIgnoredDeps();
    Path manifestDir = manifest.toAbsolutePath().getParent();
    String listJson = getUvPipListOutput(manifestDir);
    UvDependencyData data = buildDependencyGraph(manifestDir, listJson);

    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    sbom.addRoot(
        toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());

    for (String directKey : data.directDeps) {
      UvPackage pkg = data.graph.get(directKey);
      if (pkg != null) {
        addDependencyTree(sbom.getRoot(), pkg, data.graph, sbom, new HashSet<>());
      }
    }

    String manifestContent = Files.readString(manifest);
    handleIgnoredDependencies(manifestContent, sbom);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideComponent() throws IOException {
    rejectPoetryDependencies();
    collectIgnoredDeps();
    Path manifestDir = manifest.toAbsolutePath().getParent();
    String listJson = getUvPipListOutput(manifestDir);
    Map<String, UvPackage> packages = parseUvPipList(listJson);

    Sbom sbom = SbomFactory.newInstance();
    sbom.addRoot(
        toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());

    List<String> directDeps = getDirectDependencyNames();
    for (String depName : directDeps) {
      String key = canonicalize(depName);
      UvPackage pkg = packages.get(key);
      if (pkg != null) {
        sbom.addDependency(sbom.getRoot(), toPurl(pkg.name, pkg.version), null);
      }
    }

    String manifestContent = Files.readString(manifest);
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
    PackageURL packageURL = toPurl(pkg.name, pkg.version);
    sbom.addDependency(source, packageURL, null);

    String key = canonicalize(pkg.name);
    if (!visited.add(key)) {
      return;
    }

    for (String childKey : pkg.children) {
      UvPackage child = graph.get(childKey);
      if (child != null) {
        addDependencyTree(packageURL, child, graph, sbom, visited);
      }
    }
  }

  /**
   * Builds the full dependency graph by combining {@code uv pip list --format=json} (all packages
   * with versions) and {@code uv pip show} (dependency relationships via Requires field).
   */
  UvDependencyData buildDependencyGraph(Path manifestDir, String listJson) throws IOException {
    Map<String, UvPackage> packages = parseUvPipList(listJson);

    // Get dependency relationships via uv pip show
    if (!packages.isEmpty()) {
      List<String> packageNames =
          packages.values().stream().map(pkg -> pkg.name).collect(Collectors.toList());
      String showOutput = getUvPipShowOutput(manifestDir, packageNames);
      parseUvPipShow(showOutput, packages);
    }

    List<String> directDeps =
        getDirectDependencyNames().stream()
            .map(PythonUvProvider::canonicalize)
            .filter(packages::containsKey)
            .collect(Collectors.toList());

    return new UvDependencyData(directDeps, packages);
  }

  /**
   * Parses the JSON output of {@code uv pip list --format=json}. The output is a JSON array of
   * objects with {@code name} and {@code version} fields:
   *
   * <pre>
   * [{"name": "anyio", "version": "3.6.2"}, ...]
   * </pre>
   */
  Map<String, UvPackage> parseUvPipList(String listJson) throws IOException {
    JsonNode listArray = objectMapper.readTree(listJson);
    Map<String, UvPackage> packages = new HashMap<>();
    if (listArray == null || !listArray.isArray()) {
      return packages;
    }
    for (JsonNode entry : listArray) {
      String name = entry.has("name") ? entry.get("name").asText() : null;
      String version = entry.has("version") ? entry.get("version").asText() : null;
      if (name != null) {
        String key = canonicalize(name);
        packages.put(key, new UvPackage(name, version, new ArrayList<>()));
      }
    }
    return packages;
  }

  /**
   * Parses the text output of {@code uv pip show} to extract dependency relationships. Each package
   * block is separated by {@code ---} and contains a {@code Requires:} field listing dependencies.
   */
  void parseUvPipShow(String showOutput, Map<String, UvPackage> packages) {
    List<String> blocks = splitPipShowBlocks(showOutput);
    for (String block : blocks) {
      String name = extractShowField(block, "Name:");
      if (name == null) {
        continue;
      }
      String key = canonicalize(name);
      UvPackage pkg = packages.get(key);
      if (pkg == null) {
        continue;
      }
      String requires = extractShowField(block, "Requires:");
      if (requires != null && !requires.isBlank()) {
        Arrays.stream(requires.split(","))
            .map(String::trim)
            .filter(dep -> !dep.isEmpty())
            .forEach(
                dep -> {
                  String depKey = canonicalize(dep);
                  if (packages.containsKey(depKey)) {
                    pkg.children.add(depKey);
                  }
                });
      }
    }
  }

  private List<String> splitPipShowBlocks(String showOutput) {
    return Arrays.stream(showOutput.split("\\r?\\n---\\r?\\n"))
        .filter(block -> !block.isBlank())
        .collect(Collectors.toList());
  }

  private String extractShowField(String block, String fieldName) {
    int fieldIndex = block.indexOf(fieldName);
    if (fieldIndex == -1) {
      return null;
    }
    String afterField = block.substring(fieldIndex + fieldName.length());
    int endOfLine = afterField.indexOf('\n');
    if (endOfLine == -1) {
      return afterField.trim();
    }
    return afterField.substring(0, endOfLine).trim();
  }

  String getUvPipListOutput(Path manifestDir) {
    String envValue = Environment.get(PROP_TRUSTIFY_DA_UV_PIP_LIST);
    if (envValue != null && !envValue.isBlank()) {
      return envValue;
    }

    String[] cmd = {uvExecutable, "pip", "list", "--format=json"};
    Operations.ProcessExecOutput result =
        Operations.runProcessGetFullOutput(manifestDir, cmd, null);
    if (result.getExitCode() != 0) {
      throw new RuntimeException(
          String.format(
              "uv pip list command failed with exit code %d: %s",
              result.getExitCode(), result.getError()));
    }
    return result.getOutput();
  }

  String getUvPipShowOutput(Path manifestDir, List<String> packageNames) {
    String envValue = Environment.get(PROP_TRUSTIFY_DA_UV_PIP_SHOW);
    if (envValue != null && !envValue.isBlank()) {
      return envValue;
    }

    List<String> cmdParts = new ArrayList<>();
    cmdParts.add(uvExecutable);
    cmdParts.add("pip");
    cmdParts.add("show");
    cmdParts.addAll(packageNames);

    String[] cmd = cmdParts.toArray(new String[0]);
    Operations.ProcessExecOutput result =
        Operations.runProcessGetFullOutput(manifestDir, cmd, null);
    if (result.getExitCode() != 0) {
      throw new RuntimeException(
          String.format(
              "uv pip show command failed with exit code %d: %s",
              result.getExitCode(), result.getError()));
    }
    return result.getOutput();
  }

  private List<String> getDirectDependencyNames() throws IOException {
    TomlParseResult toml = getToml();
    List<String> deps = new ArrayList<>();
    TomlArray projectDeps = toml.getArray("project.dependencies");
    if (projectDeps != null) {
      for (int i = 0; i < projectDeps.size(); i++) {
        String dep = projectDeps.getString(i);
        deps.add(PythonControllerBase.getDependencyName(dep));
      }
    }
    return deps;
  }

  static String canonicalize(String name) {
    return name.toLowerCase().replaceAll("[-_.]+", "-");
  }

  // --- TOML parsing (shared with PythonPyprojectProvider) ---

  private TomlParseResult getToml() throws IOException {
    if (cachedToml == null) {
      cachedToml = PyprojectTomlUtils.parseToml(manifest);
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
    return LicenseUtils.readLicenseFile(manifest);
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
    collectedIgnoredDeps = PyprojectTomlUtils.collectIgnoredDeps(manifest, getToml());
  }

  static final class UvPackage {
    final String name;
    final String version;
    final List<String> children;

    UvPackage(String name, String version, List<String> children) {
      this.name = name;
      this.version = version;
      this.children = children;
    }
  }

  static final class UvDependencyData {
    final List<String> directDeps;
    final Map<String, UvPackage> graph;

    UvDependencyData(List<String> directDeps, Map<String, UvPackage> graph) {
      this.directDeps = directDeps;
      this.graph = graph;
    }
  }
}
