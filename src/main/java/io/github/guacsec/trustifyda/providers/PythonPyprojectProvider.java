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
import io.github.guacsec.trustifyda.utils.PythonControllerBase;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

/**
 * Provider for Python projects using {@code pyproject.toml} with <a
 * href="https://peps.python.org/pep-0621/">PEP 621</a> {@code [project.dependencies]}.
 *
 * <p>Dependency resolution is performed via {@code pip install --dry-run --ignore-installed
 * --report - .}, which produces a JSON installation report containing the full dependency graph.
 *
 * <p><strong>Poetry is not supported.</strong> If the manifest contains {@code
 * [tool.poetry.dependencies]}, both {@link #provideStack()} and {@link #provideComponent()} will
 * throw an {@link IllegalStateException}.
 */
public final class PythonPyprojectProvider extends PythonProvider {

  private static final Logger log =
      LoggersFactory.getLogger(PythonPyprojectProvider.class.getName());

  static final String PROP_TRUSTIFY_DA_PIP_REPORT = "TRUSTIFY_DA_PIP_REPORT";

  private static final Pattern DEP_NAME_PATTERN =
      Pattern.compile("^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)");
  private static final Pattern EXTRA_MARKER_PATTERN = Pattern.compile(";\\s*.*extra\\s*==");

  private Set<String> collectedIgnoredDeps;
  private TomlParseResult cachedToml;

  public PythonPyprojectProvider(Path manifest) {
    super(manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    rejectPoetryDependencies();
    collectIgnoredDeps();
    String reportJson = getPipReportOutput(manifestPath.toAbsolutePath().getParent());
    PipReportData data = parsePipReport(reportJson);

    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    sbom.addRoot(
        toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());

    for (String directKey : data.directDeps) {
      PipPackage pkg = data.graph.get(directKey);
      if (pkg != null) {
        addDependencyTree(sbom.getRoot(), pkg, data.graph, sbom, new HashSet<>());
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
    String reportJson = getPipReportOutput(manifestPath.toAbsolutePath().getParent());
    PipReportData data = parsePipReport(reportJson);

    Sbom sbom = SbomFactory.newInstance();
    sbom.addRoot(
        toPurl(getRootComponentName(), getRootComponentVersion()), readLicenseFromManifest());

    for (String directKey : data.directDeps) {
      PipPackage pkg = data.graph.get(directKey);
      if (pkg != null) {
        sbom.addDependency(sbom.getRoot(), toPurl(pkg.name, pkg.version), null);
      }
    }

    String manifestContent = Files.readString(manifestPath);
    handleIgnoredDependencies(manifestContent, sbom);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private void addDependencyTree(
      PackageURL source,
      PipPackage pkg,
      Map<String, PipPackage> graph,
      Sbom sbom,
      Set<String> visited) {
    PackageURL packageURL = toPurl(pkg.name, pkg.version);
    sbom.addDependency(source, packageURL, null);

    String key = canonicalize(pkg.name);
    if (!visited.add(key)) {
      return;
    }

    for (String childKey : pkg.children) {
      PipPackage child = graph.get(childKey);
      if (child != null) {
        addDependencyTree(packageURL, child, graph, sbom, visited);
      }
    }
  }

  String getPipReportOutput(Path manifestDir) {
    String envValue = Environment.get(PROP_TRUSTIFY_DA_PIP_REPORT);
    if (envValue != null && !envValue.isBlank()) {
      return new String(Base64.getDecoder().decode(envValue), StandardCharsets.UTF_8);
    }

    String pip = findPipBinary();
    String[] cmd = {pip, "install", "--dry-run", "--ignore-installed", "--report", "-", "."};
    Operations.ProcessExecOutput result =
        Operations.runProcessGetFullOutput(manifestDir, cmd, null);
    if (result.getExitCode() != 0) {
      throw new RuntimeException(
          String.format(
              "pip report command failed with exit code %d: %s",
              result.getExitCode(), result.getError()));
    }
    return result.getOutput();
  }

  private String findPipBinary() {
    String pip = Operations.getCustomPathOrElse("pip3");
    try {
      Operations.runProcess(pip, "--version");
      return pip;
    } catch (Exception e) {
      pip = Operations.getCustomPathOrElse("pip");
      Operations.runProcess(pip, "--version");
      return pip;
    }
  }

  /**
   * Parses the JSON document produced by {@code pip install --dry-run --ignore-installed --report}.
   * That output is pip’s <em>installation report</em>: a single object describing the resolved
   * dependency set, not a log file.
   *
   * <p><b>Top-level shape (fields this code uses)</b>
   *
   * <ul>
   *   <li>{@code install} — JSON array of one object per distribution pip would install. Other
   *       top-level keys (e.g. {@code version}, {@code pip_version}) are ignored here.
   * </ul>
   *
   * <p><b>Each element of {@code install}</b>
   *
   * <ul>
   *   <li>{@code download_info} — Where the distribution comes from. The <em>project root</em> (the
   *       {@code .} passed to pip) is identified by the presence of {@code dir_info} (often {@code
   *       {}}) under {@code download_info}. Every other entry is treated as a resolved dependency
   *       package (wheels/sdists typically use {@code archive_info} instead).
   *   <li>{@code metadata} — Core package metadata, aligned with core metadata fields:
   *       <ul>
   *         <li>{@code name}, {@code version} — Distribution name and version (strings).
   *         <li>{@code requires_dist} — Optional array of PEP 508 requirement strings (e.g. {@code
   *             "requests>=2.0"}, {@code "foo; extra == \"bar\""}). Version specifiers and
   *             environment markers appear after the name; optional dependencies use {@code extra
   *             == "..."} markers, which this parser skips when building edges.
   *       </ul>
   * </ul>
   *
   * <p><b>How this method interprets the report</b>
   *
   * <ul>
   *   <li>The entry whose {@code download_info} contains {@code dir_info} is the <em>root</em>
   *       package. Its {@code metadata.requires_dist} names the <em>direct</em> dependencies.
   *   <li>All other {@code install} entries contribute nodes in the dependency graph ({@code
   *       metadata.name} / {@code version}).
   *   <li>Edges are derived from each node’s {@code requires_dist}: the first token of each
   *       requirement is taken as the dependency name; the edge is kept only if that name resolves
   *       to another node in the graph (after canonicalization).
   * </ul>
   *
   * @param reportJson raw UTF-8 JSON text from pip’s {@code --report} output
   * @return direct dependency keys (canonicalized names) and a map of graph nodes; empty if {@code
   *     install} is missing or not an array
   * @throws IOException if {@code reportJson} is not valid JSON
   * @see <a href="https://pip.pypa.io/en/stable/reference/installation-report/">pip installation
   *     report</a>
   */
  PipReportData parsePipReport(String reportJson) throws IOException {
    JsonNode report = objectMapper.readTree(reportJson);
    JsonNode installArray = report.get("install");
    if (installArray == null || !installArray.isArray()) {
      return new PipReportData(List.of(), Map.of());
    }

    // Find root entry (has dir_info in download_info) and collect non-root packages
    JsonNode rootEntry = null;
    List<JsonNode> nonRootPackages = new ArrayList<>();
    for (JsonNode entry : installArray) {
      JsonNode downloadInfo = entry.get("download_info");
      if (rootEntry == null && downloadInfo != null && downloadInfo.has("dir_info")) {
        rootEntry = entry;
      } else {
        nonRootPackages.add(entry);
      }
    }

    if (rootEntry == null && !nonRootPackages.isEmpty()) {
      log.warning(
          "pip report contains packages but no root entry (dir_info);"
              + " dependency tree will be empty");
    }

    // Extract direct dependency names from root's requires_dist (LinkedHashSet preserves order)
    Set<String> directDepNames = new LinkedHashSet<>();
    if (rootEntry != null) {
      JsonNode metadata = rootEntry.get("metadata");
      if (metadata != null) {
        JsonNode requiresDist = metadata.get("requires_dist");
        if (requiresDist != null && requiresDist.isArray()) {
          for (JsonNode req : requiresDist) {
            String reqStr = req.asText();
            if (hasExtraMarker(reqStr)) {
              continue;
            }
            String name = extractDepName(reqStr);
            if (name != null) {
              directDepNames.add(canonicalize(name));
            }
          }
        }
      }
    }

    // Build graph from non-root packages
    Map<String, PipPackage> graph = new HashMap<>();
    for (JsonNode pkg : nonRootPackages) {
      JsonNode metadata = pkg.get("metadata");
      if (metadata == null) {
        continue;
      }
      String name = metadata.has("name") ? metadata.get("name").asText() : null;
      String version = metadata.has("version") ? metadata.get("version").asText() : null;
      if (name == null) {
        continue;
      }
      String key = canonicalize(name);
      graph.put(key, new PipPackage(name, version, new ArrayList<>()));
    }

    // Build children from each package's requires_dist
    for (JsonNode pkg : nonRootPackages) {
      JsonNode metadata = pkg.get("metadata");
      if (metadata == null) {
        continue;
      }
      String name = metadata.has("name") ? metadata.get("name").asText() : null;
      if (name == null) {
        continue;
      }
      String key = canonicalize(name);
      PipPackage pipPkg = graph.get(key);
      if (pipPkg == null) {
        continue;
      }
      JsonNode requiresDist = metadata.get("requires_dist");
      if (requiresDist == null || !requiresDist.isArray()) {
        continue;
      }
      for (JsonNode req : requiresDist) {
        String reqStr = req.asText();
        if (hasExtraMarker(reqStr)) {
          continue;
        }
        String depName = extractDepName(reqStr);
        if (depName == null) {
          continue;
        }
        String depKey = canonicalize(depName);
        if (graph.containsKey(depKey)) {
          pipPkg.children.add(depKey);
        }
      }
    }

    List<String> directDeps =
        directDepNames.stream().filter(graph::containsKey).collect(Collectors.toList());
    return new PipReportData(directDeps, graph);
  }

  static boolean hasExtraMarker(String req) {
    return EXTRA_MARKER_PATTERN.matcher(req).find();
  }

  static String extractDepName(String req) {
    Matcher m = DEP_NAME_PATTERN.matcher(req);
    return m.find() ? m.group(1) : null;
  }

  static String canonicalize(String name) {
    return name.toLowerCase().replaceAll("[-_.]+", "-");
  }

  private TomlParseResult getToml() throws IOException {
    if (cachedToml == null) {
      TomlParseResult parsed = Toml.parse(manifestPath);
      if (parsed.hasErrors()) {
        throw new IOException(
            "Invalid pyproject.toml format: " + parsed.errors().get(0).getMessage());
      }
      cachedToml = parsed;
    }
    return cachedToml;
  }

  @Override
  protected String getRootComponentName() {
    try {
      TomlParseResult toml = getToml();
      String name = toml.getString("project.name");
      if (name != null && !name.isBlank()) {
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
      TomlParseResult toml = getToml();
      String version = toml.getString("project.version");
      if (version != null && !version.isBlank()) {
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
      TomlParseResult toml = getToml();
      String license = toml.getString("project.license");
      if (license != null && !license.isBlank()) {
        return license;
      }
      // PEP 639: license may be in project.license.text
      String licenseText = toml.getString("project.license.text");
      if (licenseText != null && !licenseText.isBlank()) {
        return licenseText;
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
    TomlParseResult toml = getToml();
    TomlTable poetryDeps = toml.getTable("tool.poetry.dependencies");
    if (poetryDeps != null) {
      throw new IllegalStateException(
          "Poetry dependencies in pyproject.toml are not supported."
              + " Please use PEP 621 [project.dependencies] format instead.");
    }
  }

  private void collectIgnoredDeps() throws IOException {
    TomlParseResult toml = getToml();
    List<String> rawLines = Files.readAllLines(manifestPath);
    collectedIgnoredDeps = new HashSet<>();

    // [project.dependencies] - PEP 621
    TomlArray projectDeps = toml.getArray("project.dependencies");
    if (projectDeps != null) {
      for (int i = 0; i < projectDeps.size(); i++) {
        String dep = projectDeps.getString(i);
        checkIgnored(rawLines, dep, dep);
      }
    }
  }

  List<String> parseDependencyStrings() throws IOException {
    collectIgnoredDeps();
    TomlParseResult toml = getToml();
    List<String> deps = new ArrayList<>();

    TomlArray projectDeps = toml.getArray("project.dependencies");
    if (projectDeps != null) {
      for (int i = 0; i < projectDeps.size(); i++) {
        deps.add(projectDeps.getString(i));
      }
    }

    return deps;
  }

  private void checkIgnored(List<String> rawLines, String searchToken, String depIdentifier) {
    for (String line : rawLines) {
      if (line.contains(searchToken) && containsIgnorePattern(line)) {
        collectedIgnoredDeps.add(depIdentifier);
        break;
      }
    }
  }

  static final class PipPackage {
    final String name;
    final String version;
    final List<String> children;

    PipPackage(String name, String version, List<String> children) {
      this.name = name;
      this.version = version;
      this.children = children;
    }
  }

  static final class PipReportData {
    final List<String> directDeps;
    final Map<String, PipPackage> graph;

    PipReportData(List<String> directDeps, Map<String, PipPackage> graph) {
      this.directDeps = directDeps;
      this.graph = graph;
    }
  }
}
