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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.providers.rust.model.CargoDep;
import io.github.guacsec.trustifyda.providers.rust.model.CargoDepKind;
import io.github.guacsec.trustifyda.providers.rust.model.CargoMetadata;
import io.github.guacsec.trustifyda.providers.rust.model.CargoNode;
import io.github.guacsec.trustifyda.providers.rust.model.CargoPackage;
import io.github.guacsec.trustifyda.providers.rust.model.DependencyInfo;
import io.github.guacsec.trustifyda.providers.rust.model.ProjectInfo;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.sbom.SbomFactory;
import io.github.guacsec.trustifyda.tools.Ecosystem.Type;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.IgnorePatternDetector;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import org.tomlj.Toml;
import org.tomlj.TomlParseResult;

/**
 * Concrete implementation of the {@link Provider} used for converting dependency trees for Rust
 * projects (Cargo.toml) into a SBOM content for Component analysis or Stack analysis.
 */
public final class CargoProvider extends Provider {

  private static final ObjectMapper MAPPER =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  private static final Logger log = LoggersFactory.getLogger(CargoProvider.class.getName());
  private static final String VIRTUAL_VERSION = "1.0.0";
  private static final String PACKAGE_NAME = "package.name";
  private static final String PACKAGE_VERSION = "package.version";
  private static final String PACKAGE_VERSION_WORKSPACE = "package.version.workspace";
  private static final String WORKSPACE_PACKAGE_VERSION = "workspace.package.version";
  private static final long TIMEOUT =
      Long.parseLong(System.getProperty("trustify.cargo.timeout.seconds", "5"));
  private final String cargoExecutable;

  private void addDependencies(
      Sbom sbom,
      PackageURL root,
      Set<String> ignoredDeps,
      AnalysisType analysisType,
      ProjectInfo projectInfo) {
    try {
      CargoMetadata metadata = executeCargoMetadata();
      if (metadata != null && metadata.resolve() != null && metadata.resolve().nodes() != null) {
        // Build maps and find root once, reuse for better performance
        Map<String, CargoPackage> packageMap = buildPackageMap(metadata);
        Map<String, CargoNode> nodeMap = buildNodeMap(metadata);
        CargoNode rootNode = findRootNodeForAnalysis(metadata, nodeMap, projectInfo);

        if (rootNode == null) {
          return;
        }

        switch (analysisType) {
          case STACK -> {
            // Set to track added dependencies for deduplication
            Set<String> addedDependencies = new HashSet<>();
            Set<String> visitedNodes = new HashSet<>();
            // Recursively process dependencies starting from root
            processDependencyNode(
                rootNode,
                root,
                nodeMap,
                packageMap,
                ignoredDeps,
                sbom,
                addedDependencies,
                visitedNodes);
          }
          case COMPONENT ->
              processDirectDependencies(rootNode, ignoredDeps, sbom, root, packageMap);
        }
      }
    } catch (Exception e) {
      log.severe("Unexpected error during " + analysisType + " analysis: " + e.getMessage());
    }
  }

  @Override
  public void validateLockFile(Path lockFileDir) {
    Path actualLockFileDir = findOutermostCargoTomlDirectory(lockFileDir);
    if (!Files.isRegularFile(actualLockFileDir.resolve("Cargo.lock"))) {
      throw new IllegalStateException(
          "Cargo.lock does not exist or is not supported. Execute 'cargo build' to generate it.");
    }
  }

  private Path findOutermostCargoTomlDirectory(Path startDir) {
    Path current = startDir.getParent();
    Path outermost = startDir;
    while (current != null) {
      if (Files.exists(current.resolve("Cargo.toml"))) {
        outermost = current;
      }
      current = current.getParent();
    }
    return outermost;
  }

  private CargoMetadata executeCargoMetadata() throws IOException, InterruptedException {
    Path workingDir = manifest.getParent();

    if (debugLoggingIsNeeded()) {
      log.info("Executing cargo metadata for full dependency resolution with resolved versions");
      log.info("Cargo executable: " + cargoExecutable);
      log.info("Working directory: " + workingDir);
      log.info("Timeout: " + TIMEOUT + " seconds");
    }

    ProcessBuilder pb = new ProcessBuilder(cargoExecutable, "metadata", "--format-version", "1");
    pb.directory(workingDir.toFile());
    Process process = pb.start();

    final StringBuilder outputBuilder = new StringBuilder();
    final Exception[] readException = {null};

    Thread readerThread =
        new Thread(
            () -> {
              try (var reader =
                  new java.io.BufferedReader(
                      new java.io.InputStreamReader(
                          process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                  outputBuilder.append(line).append('\n');
                }
              } catch (IOException e) {
                readException[0] = e;
              }
            });
    readerThread.setDaemon(true);
    readerThread.start();

    boolean finished = process.waitFor(TIMEOUT, TimeUnit.SECONDS);

    if (!finished) {
      process.destroyForcibly();
      try {
        process.waitFor(5, TimeUnit.SECONDS);
      } catch (InterruptedException ignored) {
      }
      readerThread.interrupt();
      throw new InterruptedException("cargo metadata timed out after " + TIMEOUT + " seconds");
    }

    int exitCode = process.exitValue();

    try {
      readerThread.join(5000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }

    if (readException[0] != null) {
      throw new IOException(
          "Failed to read cargo metadata output: " + readException[0].getMessage(),
          readException[0]);
    }

    String output = outputBuilder.toString();
    if (exitCode != 0 || output.trim().isEmpty()) {
      return null;
    }

    try {
      CargoMetadata metadata = MAPPER.readValue(output, CargoMetadata.class);
      if (debugLoggingIsNeeded()) {
        log.info("Successfully parsed cargo metadata JSON");
        log.info(
            "Packages found: " + (metadata.packages() != null ? metadata.packages().size() : 0));
        log.info(
            "Resolve graph nodes: "
                + (metadata.resolve() != null && metadata.resolve().nodes() != null
                    ? metadata.resolve().nodes().size()
                    : 0));
        log.info(
            "Workspace members: "
                + (metadata.workspaceMembers() != null ? metadata.workspaceMembers().size() : 0));
        if (metadata.resolve() != null) {
          log.info("Resolve root: " + metadata.resolve().root());
        }
      }
      return metadata;
    } catch (Exception e) {
      log.severe("Failed to parse cargo metadata JSON: " + e.getMessage());
      return null;
    }
  }

  private Map<String, CargoNode> buildNodeMap(CargoMetadata metadata) {
    Map<String, CargoNode> nodeMap = new HashMap<>();
    for (CargoNode node : metadata.resolve().nodes()) {
      nodeMap.put(node.id(), node);
    }
    return nodeMap;
  }

  private CargoNode findRootNodeForAnalysis(
      CargoMetadata metadata, Map<String, CargoNode> nodeMap, ProjectInfo projectInfo) {
    /* The package in the current working directory (if --manifest-path is not given).
    This is null if there is a virtual workspace. Otherwise, it is
    the Package ID of the package.
    */
    String rootId = metadata.resolve().root();
    // Handle workspace-only projects (no root package)
    if (rootId == null) {
      return createRootNodeFromVirtualWorkspace(metadata, nodeMap, projectInfo);
    }
    return nodeMap.get(rootId);
  }

  private CargoNode createRootNodeFromVirtualWorkspace(
      CargoMetadata metadata, Map<String, CargoNode> nodeMap, ProjectInfo projectInfo) {
    if (metadata.workspaceMembers() == null || metadata.workspaceMembers().isEmpty()) {
      log.warning("No workspace members found for workspace-only project");
      return null;
    }

    Map<String, CargoDep> depMap = new LinkedHashMap<>();

    if (debugLoggingIsNeeded()) {
      log.info(
          "Collecting dependencies from "
              + metadata.workspaceMembers().size()
              + " workspace members");
    }

    for (String memberId : metadata.workspaceMembers()) {
      CargoNode memberNode = nodeMap.get(memberId);
      if (memberNode != null && memberNode.deps() != null) {
        log.fine("Adding dependencies from workspace member: " + memberId);
        for (CargoDep dep : memberNode.deps()) {
          depMap.putIfAbsent(dep.pkg(), dep);
        }
      }
    }

    if (debugLoggingIsNeeded()) {
      log.info(
          "Created virtual root with "
              + depMap.size()
              + " unique dependencies from workspace members");
    }

    // Create a virtual root node with combined dependencies
    // Use the actual workspace name/version from ProjectInfo
    String virtualRootId = String.format("%s#%s", projectInfo.name(), projectInfo.version());
    return new CargoNode(virtualRootId, null, new ArrayList<>(depMap.values()));
  }

  /** Process all direct dependencies from root node using resolved dep_kinds */
  private void processDirectDependencies(
      CargoNode rootNode,
      Set<String> ignoredDeps,
      Sbom sbom,
      PackageURL root,
      Map<String, CargoPackage> packageMap) {

    if (rootNode.deps() == null) {
      log.warning("Root node has no deps for component analysis");
      return;
    }

    if (debugLoggingIsNeeded()) {
      log.info(
          "Processing "
              + rootNode.deps().size()
              + " direct dependencies for component analysis (using resolved dep_kinds)");
    }

    for (CargoDep dep : rootNode.deps()) {
      log.fine("Processing dependency: " + dep.name() + " -> " + dep.pkg());
      DependencyInfo childInfo = getPackageInfo(dep.pkg(), packageMap);
      if (childInfo == null) {
        log.warning("Package not found in metadata: " + dep.pkg());
        continue;
      }
      log.fine("Found dependency: " + childInfo.name() + " v" + childInfo.version());
      if (shouldSkipDependency(dep, ignoredDeps)) {
        continue;
      }

      try {
        PackageURL packageUrl =
            new PackageURL(
                Type.CARGO.getType(), null, childInfo.name(), childInfo.version(), null, null);
        sbom.addDependency(root, packageUrl, null);
        if (debugLoggingIsNeeded()) {
          log.info(
              "✅ Added direct dependency: "
                  + childInfo.name()
                  + " v"
                  + childInfo.version()
                  + " (exact resolved version)");
        }
      } catch (Exception e) {
        log.warning("Failed to add direct dependency " + childInfo.name() + ": " + e.getMessage());
      }
    }
  }

  private boolean shouldSkipDependency(CargoDep dep, Set<String> ignoredDeps) {
    if (ignoredDeps.contains(dep.name())) {
      return true;
    }

    if (dep.depKinds() == null || dep.depKinds().isEmpty()) {
      return false;
    }

    boolean hasNormal = false;

    for (CargoDepKind depKind : dep.depKinds()) {
      if (depKind.kind() == null) {
        hasNormal = true;
        break;
      }
    }

    return !hasNormal;
  }

  private void processDependencyNode(
      CargoNode node,
      PackageURL parent,
      Map<String, CargoNode> nodeMap,
      Map<String, CargoPackage> packageMap,
      Set<String> ignoredDeps,
      Sbom sbom,
      Set<String> addedDependencies,
      Set<String> visitedNodes) {

    if (!visitedNodes.add(node.id()) || node.deps() == null) {
      return;
    }

    for (CargoDep dep : node.deps()) {
      DependencyInfo childInfo = getPackageInfo(dep.pkg(), packageMap);
      if (childInfo == null) {
        log.fine("Package not found in metadata for stack analysis: " + dep.pkg());
        continue;
      }

      if (shouldSkipDependency(dep, ignoredDeps)) {
        continue;
      }

      try {
        PackageURL childUrl =
            new PackageURL(
                Type.CARGO.getType(), null, childInfo.name(), childInfo.version(), null, null);

        // Create unique key for deduplication using stable identifiers
        String relationshipKey = parent.getCoordinates() + "->" + childUrl.getCoordinates();

        if (!addedDependencies.contains(relationshipKey)) {
          sbom.addDependency(parent, childUrl, null);
          addedDependencies.add(relationshipKey);

          if (debugLoggingIsNeeded()) {
            log.info("Added dependency: " + childInfo.name() + " v" + childInfo.version());
          }

          // Recursively process child dependencies
          CargoNode childNode = nodeMap.get(dep.pkg());
          if (childNode != null) {
            processDependencyNode(
                childNode,
                childUrl,
                nodeMap,
                packageMap,
                ignoredDeps,
                sbom,
                addedDependencies,
                visitedNodes);
          }
        }
      } catch (Exception e) {
        log.warning("Failed to add dependency " + childInfo.name() + ": " + e.getMessage());
      }
    }
  }

  private Map<String, CargoPackage> buildPackageMap(CargoMetadata metadata) {
    Map<String, CargoPackage> packageMap = new HashMap<>();
    if (metadata.packages() != null) {
      for (CargoPackage pkg : metadata.packages()) {
        packageMap.put(pkg.id(), pkg);
      }
    }
    if (debugLoggingIsNeeded()) {
      log.info("Built package map with " + packageMap.size() + " packages");
    }
    return packageMap;
  }

  private DependencyInfo getPackageInfo(String packageId, Map<String, CargoPackage> packageMap) {
    CargoPackage pkg = packageMap.get(packageId);
    if (pkg == null) {
      log.warning("Package not found in metadata: " + packageId);
      return null;
    }
    return new DependencyInfo(pkg.name(), pkg.version());
  }

  public CargoProvider(Path manifest) {
    super(Type.CARGO, manifest);
    this.cargoExecutable = Operations.getExecutable("cargo", "--version");

    if (cargoExecutable != null) {
      log.info("Found cargo executable: " + cargoExecutable);
    } else {
      log.warning("Cargo executable not found - dependency analysis will not work");
    }
    log.info("Initialized RustProvider for manifest: " + manifest);
  }

  @Override
  public Content provideComponent() throws IOException {
    Sbom sbom = createSbom(false);
    return new Content(sbom.getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideStack() throws IOException {
    Sbom sbom = createSbom(true);
    return new Content(sbom.getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private Sbom createSbom(boolean includeTransitiveDependencies) throws IOException {
    if (!Files.exists(manifest) || !Files.isRegularFile(manifest)) {
      throw new IOException("Cargo.toml not found: " + manifest);
    }

    TomlParseResult tomlResult = Toml.parse(manifest);
    if (tomlResult.hasErrors()) {
      throw new IOException(
          "Invalid Cargo.toml format: " + tomlResult.errors().get(0).getMessage());
    }

    Sbom sbom = SbomFactory.newInstance();
    ProjectInfo projectInfo = parseCargoToml(tomlResult);

    try {
      var root =
          new PackageURL(
              Type.CARGO.getType(), null, projectInfo.name(), projectInfo.version(), null, null);
      sbom.addRoot(root);

      String cargoContent = Files.readString(manifest, StandardCharsets.UTF_8);
      Set<String> ignoredDeps = getIgnoredDependencies(tomlResult, cargoContent);

      if (includeTransitiveDependencies) {
        addDependencies(sbom, root, ignoredDeps, AnalysisType.STACK, projectInfo);
      } else {
        addDependencies(sbom, root, ignoredDeps, AnalysisType.COMPONENT, projectInfo);
      }
      return sbom;
    } catch (Exception e) {
      throw new RuntimeException("Failed to create Rust SBOM", e);
    }
  }

  private ProjectInfo parseCargoToml(TomlParseResult result) throws IOException {
    String packageName = result.getString(PACKAGE_NAME);
    String packageVersion = null;
    if (packageName != null) {
      Object versionValue = result.get(PACKAGE_VERSION);
      if (versionValue instanceof String) {
        packageVersion = (String) versionValue;
      } else if (versionValue != null) {
        // Could be a table like { workspace = true }
        Boolean isWorkspaceVersion = result.getBoolean(PACKAGE_VERSION_WORKSPACE);
        if (Boolean.TRUE.equals(isWorkspaceVersion)) {
          // Inherit version from workspace
          packageVersion = result.getString(WORKSPACE_PACKAGE_VERSION);
        }
      }
      if (debugLoggingIsNeeded()) {
        log.info(
            "Parsed project info: name="
                + packageName
                + ", version="
                + (packageVersion != null ? packageVersion : VIRTUAL_VERSION));
      }
      return new ProjectInfo(
          packageName, packageVersion != null ? packageVersion : VIRTUAL_VERSION);
    }
    // Check for workspace section as fallback (when there's no [package] section)
    boolean hasWorkspace = result.contains("workspace");
    if (hasWorkspace) {
      String workspaceVersion = result.getString(WORKSPACE_PACKAGE_VERSION);
      String dirName = getDirectoryName();
      if (debugLoggingIsNeeded()) {
        log.info(
            "Using workspace fallback: name="
                + dirName
                + ", version="
                + (workspaceVersion != null ? workspaceVersion : VIRTUAL_VERSION));
      }
      return new ProjectInfo(
          dirName, workspaceVersion != null ? workspaceVersion : VIRTUAL_VERSION);
    }
    throw new IOException("Invalid Cargo.toml: no [package] or [workspace] section found");
  }

  private String getDirectoryName() {
    Path parent = manifest.getParent();
    if (parent != null && parent.getFileName() != null) {
      return parent.getFileName().toString();
    }
    return "rust-workspace";
  }

  private Set<String> getIgnoredDependencies(TomlParseResult result, String content) {
    Set<String> ignoredDeps = new HashSet<>();
    if (content == null || content.isEmpty()) {
      log.fine("Empty content provided for ignore dependencies detection");
      return ignoredDeps;
    }

    try {
      Set<String> allDependencies = collectAllDependencies(result);
      if (debugLoggingIsNeeded()) {
        log.info("Found " + allDependencies.size() + " total dependencies in Cargo.toml");
      }
      ignoredDeps = findIgnoredDependencies(content, allDependencies);
      if (debugLoggingIsNeeded()) {
        log.fine("Found " + ignoredDeps.size() + " ignored dependencies: " + ignoredDeps);
      }
    } catch (Exception e) {
      log.severe(
          "Unexpected error during ignore detection for " + manifest + " - " + e.getMessage());
    }
    return ignoredDeps;
  }

  private Set<String> collectAllDependencies(TomlParseResult result) {
    Set<String> allDeps = new HashSet<>();
    addDependenciesFromSection(result, "dependencies", allDeps);
    addDependenciesFromSection(result, "workspace.dependencies", allDeps);
    addDependenciesFromSection(result, "workspace.build-dependencies", allDeps);
    return allDeps;
  }

  private void addDependenciesFromSection(
      TomlParseResult result, String sectionPath, Set<String> allDeps) {
    if (result.contains(sectionPath)) {
      var sectionTable = result.getTable(sectionPath);
      if (sectionTable != null) {
        allDeps.addAll(sectionTable.keySet());
      }
    }
  }

  private Set<String> findIgnoredDependencies(String content, Set<String> allDependencies) {
    Set<String> ignoredDeps = new HashSet<>();
    String[] lines = content.split("\\r?\\n");

    for (String line : lines) {
      String trimmed = line.trim();
      if (trimmed.isEmpty() || !IgnorePatternDetector.containsIgnorePattern(line)) {
        continue;
      }
      // Check if this line contains any of our dependencies
      for (String depName : allDependencies) {
        if (lineContainsDependency(trimmed, depName)) {
          ignoredDeps.add(depName);
        }
      }
    }
    return ignoredDeps;
  }

  private boolean lineContainsDependency(String trimmed, String depName) {
    // Table format: [*.dependencies.depname] # trustify-da-ignore
    if (trimmed.startsWith("[") && trimmed.contains("." + depName + "]")) {
      return true;
    }
    // Inline format: depname = "version" # trustify-da-ignore
    if (trimmed.startsWith(depName + " ")
        || trimmed.startsWith(depName + "=")
        || trimmed.startsWith("\"" + depName + "\"")) {
      return true;
    }
    return false;
  }
}
