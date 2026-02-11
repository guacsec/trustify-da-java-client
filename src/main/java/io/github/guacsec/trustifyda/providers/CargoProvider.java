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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
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

  private CargoProjectLayout getProjectLayout(CargoMetadata metadata) {
    boolean hasRootCrate = metadata.resolve() != null && metadata.resolve().root() != null;
    boolean hasWorkspace =
        metadata.workspaceMembers() != null && !metadata.workspaceMembers().isEmpty();

    // Check if this is actually a single crate - cargo metadata includes the root crate
    // as a workspace member even for single crate projects
    if (hasRootCrate && hasWorkspace && metadata.workspaceMembers().size() == 1) {
      String rootId = metadata.resolve().root();
      String singleMember = metadata.workspaceMembers().get(0);
      if (rootId.equals(singleMember)) {
        return CargoProjectLayout.SINGLE_CRATE;
      }
    }

    if (hasRootCrate && !hasWorkspace) {
      return CargoProjectLayout.SINGLE_CRATE;
    }
    if (hasRootCrate) {
      return CargoProjectLayout.WORKSPACE_WITH_ROOT_CRATE;
    }
    if (hasWorkspace) {
      return CargoProjectLayout.WORKSPACE_VIRTUAL;
    }
    throw new IllegalStateException(
        "Invalid Cargo project layout: no root crate and no workspace members");
  }

  private void addDependencies(
      Sbom sbom,
      PackageURL root,
      Set<String> ignoredDeps,
      TomlParseResult tomlResult,
      AnalysisType analysisType) {
    try {
      CargoMetadata metadata = executeCargoMetadata();
      if (metadata == null || metadata.resolve() == null || metadata.resolve().nodes() == null) {
        return;
      }

      Map<String, CargoPackage> packageMap = buildPackageMap(metadata);
      Map<String, CargoNode> nodeMap = buildNodeMap(metadata);

      CargoProjectLayout layout = getProjectLayout(metadata);
      if (debugLoggingIsNeeded()) {
        log.info(
            "Project layout: "
                + layout
                + " (hasRoot: "
                + (metadata.resolve().root() != null)
                + ", workspaceMembers: "
                + (metadata.workspaceMembers() != null ? metadata.workspaceMembers().size() : 0)
                + ")");
      }

      switch (layout) {
        case SINGLE_CRATE ->
            handleSingleCrate(sbom, root, metadata, nodeMap, packageMap, ignoredDeps, analysisType);
        case WORKSPACE_VIRTUAL ->
            handleVirtualWorkspace(
                sbom, root, metadata, nodeMap, packageMap, ignoredDeps, tomlResult, analysisType);
        case WORKSPACE_WITH_ROOT_CRATE ->
            // Process root crate dependencies - this will naturally include any workspace
            // members that are actual dependencies via the cargo dependency graph.
            // Note: Workspace members are only included if they appear in the root crate's
            // dependency graph from cargo metadata. We don't automatically add all members
            // as dependencies since most workspace members (examples, tools, benchmarks)
            // depend ON the root crate, not the other way around.
            handleSingleCrate(sbom, root, metadata, nodeMap, packageMap, ignoredDeps, analysisType);
      }

    } catch (Exception e) {
      log.severe("Unexpected error during " + analysisType + " analysis: " + e.getMessage());
    }
  }

  private void handleSingleCrate(
      Sbom sbom,
      PackageURL root,
      CargoMetadata metadata,
      Map<String, CargoNode> nodeMap,
      Map<String, CargoPackage> packageMap,
      Set<String> ignoredDeps,
      AnalysisType analysisType) {

    CargoNode rootNode = nodeMap.get(metadata.resolve().root());
    switch (analysisType) {
      case STACK -> {
        Set<String> addedDependencies = new HashSet<>();
        Set<String> visitedNodes = new HashSet<>();
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
      case COMPONENT -> processDirectDependencies(rootNode, ignoredDeps, sbom, root, packageMap);
    }
  }

  private void handleVirtualWorkspace(
      Sbom sbom,
      PackageURL root,
      CargoMetadata metadata,
      Map<String, CargoNode> nodeMap,
      Map<String, CargoPackage> packageMap,
      Set<String> ignoredDeps,
      TomlParseResult tomlResult,
      AnalysisType analysisType) {

    switch (analysisType) {
      // For COMPONENT analysis: only include workspace dependencies from [workspace.dependencies]
      case COMPONENT ->
          processWorkspaceDependencies(sbom, root, packageMap, ignoredDeps, tomlResult);
      case STACK -> {
        // For STACK analysis: include workspace members and their dependencies
        if (debugLoggingIsNeeded()) {
          log.info(
              "Processing virtual workspace with "
                  + metadata.workspaceMembers().size()
                  + " members: "
                  + metadata.workspaceMembers());
        }
        for (String memberId : metadata.workspaceMembers()) {
          processWorkspaceMember(
              sbom, root, memberId, nodeMap, packageMap, ignoredDeps, analysisType);
        }
      }
    }
  }

  private void processWorkspaceDependencies(
      Sbom sbom,
      PackageURL root,
      Map<String, CargoPackage> packageMap,
      Set<String> ignoredDeps,
      TomlParseResult tomlResult) {

    var workspaceDepsTable = tomlResult.getTable("workspace.dependencies");
    if (debugLoggingIsNeeded()) {
      log.info("Processing " + workspaceDepsTable.keySet().size() + " workspace dependencies");
    }
    // Note: We only need dependency names from TOML, regardless of format:
    // - Simple: serde = "1.0"
    // - Table: serde = { version = "1.0", features = ["derive"] }
    // - Section: [workspace.dependencies.serde] version = "1.0"
    // The actual resolved versions come from cargo metadata packageMap, not TOML.
    for (String depName : workspaceDepsTable.keySet()) {
      if (ignoredDeps.contains(depName)) {
        continue;
      }
      CargoPackage depPackage = findPackageByName(packageMap, depName);
      try {
        PackageURL depUrl =
            new PackageURL(
                Type.CARGO.getType(), null, depPackage.name(), depPackage.version(), null, null);
        sbom.addDependency(root, depUrl, null);
      } catch (Exception e) {
        log.warning("Failed to create PackageURL for workspace dependency: " + depName);
      }
    }
  }

  private CargoPackage findPackageByName(Map<String, CargoPackage> packageMap, String name) {
    return packageMap.values().stream()
        .filter(pkg -> pkg.name().equals(name))
        .findFirst()
        .orElse(null);
  }

  @Override
  public void validateLockFile(Path lockFileDir) {
    Path actualLockFileDir = findOutermostCargoTomlDirectory(lockFileDir);
    if (!Files.isRegularFile(actualLockFileDir.resolve("Cargo.lock"))) {
      throw new IllegalStateException(
          "Cargo.lock does not exist or is not supported. Execute 'cargo build' to generate it.");
    }
  }

  /**
   * Processes an individual workspace member as an independent SBOM component. For COMPONENT
   * analysis: Only adds member as direct dependency of workspace. For STACK analysis: Also adds
   * member's transitive dependencies.
   */
  private void processWorkspaceMember(
      Sbom sbom,
      PackageURL workspaceRoot,
      String memberId,
      Map<String, CargoNode> nodeMap,
      Map<String, CargoPackage> packageMap,
      Set<String> ignoredDeps,
      AnalysisType analysisType) {

    CargoPackage memberPkg = packageMap.get(memberId);
    if (memberPkg == null) {
      log.warning("Workspace member package not found: " + memberId);
      return;
    }

    try {
      PackageURL memberUrl =
          new PackageURL(
              Type.CARGO.getType(), null, memberPkg.name(), memberPkg.version(), null, null);
      sbom.addDependency(workspaceRoot, memberUrl, null);

      if (debugLoggingIsNeeded()) {
        log.fine(
            "Processing member: "
                + memberPkg.name()
                + "@"
                + memberPkg.version()
                + " (id: "
                + memberId
                + ") for "
                + analysisType
                + " analysis");
      }

      // Only process member's dependencies for STACK analysis (transitive)
      // For COMPONENT analysis: stop here - don't process member dependencies
      if (analysisType == AnalysisType.STACK) {
        CargoNode memberNode = nodeMap.get(memberId);
        if (memberNode != null) {
          Set<String> addedDependencies = new HashSet<>();
          Set<String> visitedNodes = new HashSet<>();
          processDependencyNode(
              memberNode,
              memberUrl,
              nodeMap,
              packageMap,
              ignoredDeps,
              sbom,
              addedDependencies,
              visitedNodes);
        }
      }
    } catch (Exception e) {
      log.warning(
          "Failed to create PackageURL for member " + memberPkg.name() + ": " + e.getMessage());
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

    Process process =
        new ProcessBuilder(cargoExecutable, "metadata", "--format-version", "1")
            .directory(workingDir.toFile())
            .start();

    String output;
    try (InputStream is = process.getInputStream()) {
      output = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    boolean finished = process.waitFor(TIMEOUT, TimeUnit.SECONDS);

    int exitCode = process.exitValue();

    if (exitCode != 0) {
      String errorOutput = "";
      try (InputStream errorStream = process.getErrorStream()) {
        errorOutput = new String(errorStream.readAllBytes(), StandardCharsets.UTF_8);
      } catch (IOException e) {
        log.warning("Failed to read error stream: " + e.getMessage());
      }

      String errorMessage = "cargo metadata failed with exit code: " + exitCode;
      if (!errorOutput.isEmpty()) {
        errorMessage += ". Error: " + errorOutput.trim();
      }
      log.warning(errorMessage);
      return null;
    }

    if (output.isBlank()) {
      if (debugLoggingIsNeeded()) {
        log.warning("cargo metadata returned empty output");
      }
      return null;
    }

    if (!finished) {
      process.destroyForcibly();
      throw new InterruptedException("cargo metadata timed out after " + TIMEOUT + " seconds");
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

  private void processDirectDependencies(
      CargoNode sourceNode,
      Set<String> ignoredDeps,
      Sbom sbom,
      PackageURL sourceUrl,
      Map<String, CargoPackage> packageMap) {

    if (debugLoggingIsNeeded()) {
      log.info(
          "Processing "
              + sourceNode.deps().size()
              + " direct dependencies for component analysis (using resolved dep_kinds)");
    }

    for (CargoDep dep : sourceNode.deps()) {
      DependencyInfo childInfo = getPackageInfo(dep.pkg(), packageMap);
      if (shouldSkipDependency(dep, ignoredDeps)) {
        continue;
      }

      try {
        PackageURL packageUrl =
            new PackageURL(
                Type.CARGO.getType(), null, childInfo.name(), childInfo.version(), null, null);
        sbom.addDependency(sourceUrl, packageUrl, null);
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
    // dep.name() returns the crate name (may have underscores)
    String crateName = dep.name();
    if (ignoredDeps.contains(crateName)) {
      return true;
    }
    String packageNameFormat = crateName.replace('_', '-');
    if (!crateName.equals(packageNameFormat) && ignoredDeps.contains(packageNameFormat)) {
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
      if (shouldSkipDependency(dep, ignoredDeps)) {
        continue;
      }

      try {
        PackageURL childUrl =
            new PackageURL(
                Type.CARGO.getType(), null, childInfo.name(), childInfo.version(), null, null);

        String relationshipKey = parent.getCoordinates() + "->" + childUrl.getCoordinates();

        if (!addedDependencies.contains(relationshipKey)) {
          sbom.addDependency(parent, childUrl, null);
          addedDependencies.add(relationshipKey);

          if (debugLoggingIsNeeded()) {
            log.info("Added dependency: " + childInfo.name() + " v" + childInfo.version());
          }

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
    Sbom sbom = createSbom(AnalysisType.COMPONENT);
    return new Content(sbom.getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideStack() throws IOException {
    Sbom sbom = createSbom(AnalysisType.STACK);
    return new Content(sbom.getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private Sbom createSbom(AnalysisType analysisType) throws IOException {
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
      addDependencies(sbom, root, ignoredDeps, tomlResult, analysisType);
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
      String dirName = manifest.toAbsolutePath().getParent().getFileName().toString();
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

  private Set<String> getIgnoredDependencies(TomlParseResult result, String content) {
    Set<String> normalDependencies = collectNormalDependencies(result);
    if (debugLoggingIsNeeded()) {
      log.info("Found " + normalDependencies.size() + " normal dependencies in Cargo.toml");
    }
    // TomlParseResult doesn't retain comment, need to check ignore keyword from Cargo.toml content.
    Set<String> ignoredDeps = findIgnoredDependencies(content, normalDependencies);
    if (debugLoggingIsNeeded()) {
      log.info("Found " + ignoredDeps.size() + " ignored dependencies: " + ignoredDeps);
    }
    return ignoredDeps;
  }

  private Set<String> collectNormalDependencies(TomlParseResult result) {
    Set<String> allDeps = new HashSet<>();
    addDependenciesFromSection(result, "dependencies", allDeps);
    addDependenciesFromSection(result, "workspace.dependencies", allDeps);
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

  private Set<String> findIgnoredDependencies(String content, Set<String> normalDependencies) {
    Set<String> ignoredDeps = new HashSet<>();
    String[] lines = content.split("\\r?\\n");
    for (String line : lines) {
      String trimmed = line.trim();
      if (trimmed.isEmpty() || !IgnorePatternDetector.containsIgnorePattern(line)) {
        continue;
      }
      for (String depName : normalDependencies) {
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
