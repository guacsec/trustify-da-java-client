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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.sbom.SbomFactory;
import io.github.guacsec.trustifyda.tools.Ecosystem.Type;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.Environment;
import io.github.guacsec.trustifyda.utils.IgnorePatternDetector;
import io.github.guacsec.trustifyda.vcs.GitVersionControlSystemImpl;
import io.github.guacsec.trustifyda.vcs.TagInfo;
import io.github.guacsec.trustifyda.vcs.VersionControlSystem;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Concrete implementation of the {@link Provider} used for converting dependency trees for npm
 * projects (package.json) into a SBOM content for Stack analysis or Component analysis.
 */
public final class GoModulesProvider extends Provider {

  public static final String PROP_TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED =
      "TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED";
  private static final Logger log = LoggersFactory.getLogger(GoModulesProvider.class.getName());
  public static final String DEFAULT_MAIN_VERSION = "v0.0.0";
  private final String goExecutable;

  public String getMainModuleVersion() {
    return mainModuleVersion;
  }

  private String mainModuleVersion;

  public GoModulesProvider(Path manifest) {
    super(Type.GOLANG, manifest);
    this.goExecutable = Operations.getExecutable("go", "version");
    this.mainModuleVersion = getDefaultMainModuleVersion();
  }

  @Override
  public Content provideStack() throws IOException {
    // check for custom executable
    Sbom sbom = getDependenciesSbom(manifest, true);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideComponent() throws IOException {
    if (!Files.exists(manifest)) {
      throw new IllegalArgumentException("Missing required go.mod file: " + manifest);
    }
    if (!Files.isRegularFile(manifest)) {
      throw new IllegalArgumentException(
          "The provided manifest is not a regular file: " + manifest);
    }
    var sbom = getDependenciesSbom(manifest, false);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private PackageURL toPurl(String dependency, String delimiter) {
    try {
      int lastSlashIndex = dependency.lastIndexOf("/");
      // there is no '/' char in module/package, so there is no namespace, only name
      if (lastSlashIndex == -1) {
        String[] splitParts = dependency.split(delimiter);
        if (splitParts.length == 2) {
          return new PackageURL(
              Type.GOLANG.getType(), null, splitParts[0], splitParts[1], null, null);
        } else {
          return new PackageURL(
              Type.GOLANG.getType(), null, splitParts[0], this.mainModuleVersion, null, null);
        }
      }
      String namespace = dependency.substring(0, lastSlashIndex);
      String dependencyAndVersion = dependency.substring(lastSlashIndex + 1);
      String[] parts = dependencyAndVersion.split(delimiter);

      if (parts.length == 2) {
        return new PackageURL(Type.GOLANG.getType(), namespace, parts[0], parts[1], null, null);
        // in this case, there is no version (happens with main module), thus need to take it from
        // precalculated
        // main module version.
      } else {
        return new PackageURL(
            Type.GOLANG.getType(), namespace, parts[0], this.mainModuleVersion, null, null);
      }
    } catch (MalformedPackageURLException e) {
      throw new IllegalArgumentException(
          "Unable to parse golang module package : " + dependency, e);
    }
  }

  Sbom getDependenciesSbom(Path manifestPath, boolean buildTree) throws IOException {
    var goModulesResult = buildGoModulesDependencies(manifestPath);
    determineMainModuleVersion(manifestPath.getParent());
    Sbom sbom;
    List<PackageURL> ignoredDeps = getIgnoredDeps(manifestPath);
    boolean matchManifestVersions =
        Environment.getBoolean(Provider.PROP_MATCH_MANIFEST_VERSIONS, false);
    if (matchManifestVersions) {
      String[] goModGraphLines = goModulesResult.split(Operations.GENERIC_LINE_SEPARATOR);
      performManifestVersionsCheck(goModGraphLines, manifestPath);
    }
    if (!buildTree) {
      sbom = buildSbomFromList(goModulesResult, ignoredDeps);
    } else {
      sbom = buildSbomFromGraph(goModulesResult, ignoredDeps, manifestPath);
    }
    return sbom;
  }

  private void performManifestVersionsCheck(String[] goModGraphLines, Path manifestPath) {
    try {
      String goModLines = Files.readString(manifestPath);
      String[] lines = goModLines.split(Operations.GENERIC_LINE_SEPARATOR);
      String root = getParentVertex(goModGraphLines[0]);
      List<String> comparisonLines =
          Arrays.stream(goModGraphLines)
              .filter((line) -> line.startsWith(root))
              .map(GoModulesProvider::getChildVertex)
              .collect(Collectors.toList());
      List<String> goModDependencies = collectAllDepsFromManifest(lines, goModLines);
      comparisonLines.forEach(
          (dependency) -> {
            String[] parts = dependency.split("@");
            String version = parts[1];
            String depName = parts[0];
            goModDependencies.forEach(
                (dep) -> {
                  String[] artifactParts = dep.trim().split(" ");
                  String currentDepName = artifactParts[0];
                  String currentVersion = artifactParts[1];
                  if (currentDepName.trim().equals(depName.trim())) {
                    if (!currentVersion.trim().equals(version.trim())) {
                      throw new RuntimeException(
                          String.format(
                              "Can't continue with analysis - versions mismatch for"
                                  + " dependency name=%s, manifest version=%s, installed"
                                  + " Version=%s, if you want to allow version mismatch for"
                                  + " analysis between installed and requested packages,"
                                  + " set environment variable/setting -"
                                  + " %s=false",
                              depName,
                              currentVersion,
                              version,
                              Provider.PROP_MATCH_MANIFEST_VERSIONS));
                    }
                  }
                });
          });
    } catch (IOException e) {
      throw new RuntimeException(
          "Failed to open go.mod file for manifest versions check validation!");
    }
  }

  private List<String> collectAllDepsFromManifest(String[] lines, String goModLines) {
    // collect all deps that starts with require keyword
    List<String> result =
        Arrays.stream(lines)
            .filter((line) -> line.trim().startsWith("require") && !line.contains("("))
            .map((dep) -> dep.substring("require".length()).trim())
            .collect(Collectors.toList());

    // collect all deps that are inside `require` blocks
    String currentSegmentOfGoMod = goModLines;
    Map<String, Integer> requirePosObject = decideRequireBlockIndex(currentSegmentOfGoMod);
    while (requirePosObject.get("index") > -1) {
      String depsInsideRequirementsBlock =
          currentSegmentOfGoMod
              .substring(requirePosObject.get("index") + requirePosObject.get("length"))
              .trim();
      int endOfBlockIndex = depsInsideRequirementsBlock.indexOf(")");
      int currentIndex = 0;
      while (currentIndex < endOfBlockIndex) {
        int endOfLinePosition =
            depsInsideRequirementsBlock.indexOf(System.lineSeparator(), currentIndex);
        String dependency =
            depsInsideRequirementsBlock.substring(currentIndex, endOfLinePosition).trim();
        result.add(dependency);
        currentIndex = endOfLinePosition + 1;
      }
      currentSegmentOfGoMod = currentSegmentOfGoMod.substring(endOfBlockIndex + 1).trim();
      requirePosObject = decideRequireBlockIndex(currentSegmentOfGoMod);
    }

    return result;
  }

  private Map<String, Integer> decideRequireBlockIndex(String currentSegmentOfGoMod) {
    int index = currentSegmentOfGoMod.indexOf("require(");
    int length = "require(".length();
    if (index == -1) {
      index = currentSegmentOfGoMod.indexOf("require (");
      length = "require (".length();
      if (index == -1) {
        index = currentSegmentOfGoMod.indexOf("require  (");
        length = "require  (".length();
      }
    }
    return Map.of("index", index, "length", length);
  }

  public void determineMainModuleVersion(Path directory) {
    // TODO: The javascript api doesn't implement this method
    VersionControlSystem vcs = new GitVersionControlSystemImpl();
    if (vcs.isDirectoryRepo(directory)) {
      TagInfo latestTagInfo = vcs.getLatestTag(directory);
      if (!latestTagInfo.getTagName().trim().isEmpty()) {
        if (!latestTagInfo.isCurrentCommitPointedByTag()) {
          String nextTagVersion = vcs.getNextTagVersion(latestTagInfo);
          this.mainModuleVersion = vcs.getPseudoVersion(latestTagInfo, nextTagVersion);
        } else {
          this.mainModuleVersion = latestTagInfo.getTagName();
        }
      } else {
        if (!latestTagInfo.getCurrentCommitDigest().trim().isEmpty()) {
          this.mainModuleVersion =
              vcs.getPseudoVersion(latestTagInfo, getDefaultMainModuleVersion());
        }
      }
    }
  }

  private Sbom buildSbomFromGraph(
      String goModulesResult, List<PackageURL> ignoredDeps, Path manifestPath) {
    // Each entry contains a key of the module, and the list represents the module direct
    // dependencies , so
    // pairing of the key with each of the dependencies in a list is basically an edge in the graph.
    Map<String, List<String>> edges = new HashMap<>();
    // iterate over go mod graph line by line and create map , with each entry to contain module as
    // a key , and
    // value of list of that module' dependencies.
    List<String> linesList =
        Arrays.asList(goModulesResult.split(Operations.GENERIC_LINE_SEPARATOR));

    int startingIndex = 0;
    for (String line : linesList) {
      if (!edges.containsKey(getParentVertex(line))) {
        // Collect all direct dependencies of the current module into a list.
        List<String> deps =
            collectAllDirectDependencies(linesList.subList(startingIndex, linesList.size()), line);
        edges.put(getParentVertex(line), deps);
        startingIndex += deps.size();
      }
    }
    boolean goMvsLogicEnabled = Environment.getBoolean(PROP_TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED, true);
    if (goMvsLogicEnabled) {
      edges = getFinalPackagesVersionsForModule(edges, manifestPath);
    }
    //    Build Sbom
    String rootPackage = getParentVertex(linesList.get(0));

    PackageURL root = toPurl(rootPackage, "@");
    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    sbom.addRoot(root);
    edges.forEach(
        (key, value) -> {
          PackageURL source = toPurl(key, "@");
          value.stream()
              .filter(dep -> !isGoToolchainEntry(dep))
              .forEach(
                  dep -> {
                    PackageURL targetPurl = toPurl(dep, "@");
                    sbom.addDependency(source, targetPurl, null);
                  });
        });
    List<String> ignoredDepsPurl =
        ignoredDeps.stream().map(PackageURL::getCoordinates).collect(Collectors.toList());
    sbom.filterIgnoredDeps(ignoredDepsPurl);
    ArrayList<String> ignoredDepsByName = new ArrayList<>();
    ignoredDeps.forEach(
        purl -> {
          if (sbom.checkIfPackageInsideDependsOnList(sbom.getRoot(), purl.getName())) {
            ignoredDepsByName.add(purl.getName());
          }
        });
    sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.NAME);
    sbom.filterIgnoredDeps(ignoredDepsByName);

    return sbom;
  }

  private Map<String, List<String>> getFinalPackagesVersionsForModule(
      Map<String, List<String>> edges, Path manifestPath) {
    Operations.runProcessGetOutput(manifestPath.getParent(), "go", "mod", "download");
    String finalVersionsForAllModules =
        Operations.runProcessGetOutput(manifestPath.getParent(), "go", "list", "-m", "all");
    Map<String, String> finalModulesVersions =
        Arrays.stream(finalVersionsForAllModules.split(Operations.GENERIC_LINE_SEPARATOR))
            .filter(string -> string.trim().split(" ").length == 2)
            .collect(
                Collectors.toMap(
                    t -> t.split(" ")[0], t -> t.split(" ")[1], (first, second) -> second));
    Map<String, List<String>> listWithModifiedVersions = new HashMap<>();
    // Process all entries, including those without versions (like the root module)
    edges.forEach(
        (key, value) -> {
          // Handle both cases: module with version (module@version) and without (just module name)
          String packageWithSelectedVersion;
          if (key.contains("@")) {
            packageWithSelectedVersion = getPackageWithFinalVersion(finalModulesVersions, key);
          } else {
            // For root module or modules without version, get version from finalModulesVersions
            // or use default version
            String version = finalModulesVersions.get(key);
            if (version != null) {
              packageWithSelectedVersion = String.format("%s@%s", key, version);
            } else {
              // If not found, keep original key and append default version
              packageWithSelectedVersion = String.format("%s@%s", key, this.mainModuleVersion);
            }
          }
          List<String> packagesWithFinalVersions =
              getListOfPackagesWithFinalVersions(finalModulesVersions, value);
          listWithModifiedVersions.put(packageWithSelectedVersion, packagesWithFinalVersions);
        });

    return listWithModifiedVersions;
  }

  private List<String> getListOfPackagesWithFinalVersions(
      Map<String, String> finalModulesVersions, List<String> packages) {
    return packages.stream()
        .map(
            (packageWithVersion) ->
                getPackageWithFinalVersion(finalModulesVersions, packageWithVersion))
        .collect(Collectors.toList());
  }

  public static String getPackageWithFinalVersion(
      Map<String, String> finalModulesVersions, String packagePlusVersion) {
    String packageName = packagePlusVersion.split("@")[0];
    String finalVersion = finalModulesVersions.get(packageName);
    if (Objects.nonNull(finalVersion)) {
      return String.format("%s@%s", packageName, finalVersion);
    } else {
      return packagePlusVersion;
    }
  }

  private boolean dependencyNotToBeIgnored(List<PackageURL> ignoredDeps, PackageURL checkedPurl) {
    return ignoredDeps.stream()
        .noneMatch(
            dependencyPurl -> dependencyPurl.getCoordinates().equals(checkedPurl.getCoordinates()));
  }

  private static List<String> collectAllDirectDependencies(List<String> targetLines, String edge) {
    return targetLines.stream()
        .filter(line -> getParentVertex(line).equals(getParentVertex(edge)))
        .map(GoModulesProvider::getChildVertex)
        .filter(dep -> !isGoToolchainEntry(dep))
        .collect(Collectors.toList());
  }

  private static boolean isGoToolchainEntry(String dependency) {
    // Filter out Go toolchain entries like "go@1.18", "go@1.19", etc.
    // These are not actual dependencies but the Go toolchain itself
    return dependency.startsWith("go@");
  }

  private String buildGoModulesDependencies(Path manifestPath) {
    String[] goModulesDeps;
    goModulesDeps = new String[] {goExecutable, "mod", "graph"};

    // execute the clean command
    String goModulesOutput =
        Operations.runProcessGetOutput(manifestPath.getParent(), goModulesDeps);
    if (debugLoggingIsNeeded()) {
      log.info(
          String.format(
              "Package Manager Go Mod Graph output : %s%s",
              System.lineSeparator(), goModulesOutput));
    }
    return goModulesOutput;
  }

  private Sbom buildSbomFromList(String golangDeps, List<PackageURL> ignoredDeps) {
    String[] allModulesFlat = golangDeps.split(Operations.GENERIC_LINE_SEPARATOR);
    String parentVertex = getParentVertex(allModulesFlat[0]);
    PackageURL root = toPurl(parentVertex, "@");
    // Get only direct dependencies of root package/module, and that's it.
    List<String> deps = collectAllDirectDependencies(Arrays.asList(allModulesFlat), parentVertex);

    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    sbom.addRoot(root);
    deps.stream()
        .filter(dep -> !isGoToolchainEntry(dep))
        .forEach(
            dep -> {
              PackageURL targetPurl = toPurl(dep, "@");
              if (dependencyNotToBeIgnored(ignoredDeps, targetPurl)) {
                sbom.addDependency(root, targetPurl, null);
              }
            });
    List<String> ignoredDepsByName = new ArrayList<>();
    ignoredDeps.forEach(
        purl -> {
          if (sbom.checkIfPackageInsideDependsOnList(sbom.getRoot(), purl.getName())) {
            ignoredDepsByName.add(purl.getName());
          }
        });
    sbom.setBelongingCriteriaBinaryAlgorithm(Sbom.BelongingCondition.NAME);
    sbom.filterIgnoredDeps(ignoredDepsByName);
    return sbom;
  }

  private List<PackageURL> getIgnoredDeps(Path manifestPath) throws IOException {

    List<String> goModlines = Files.readAllLines(manifestPath);
    List<PackageURL> ignored =
        goModlines.stream()
            .filter(this::IgnoredLine)
            .map(this::extractPackageName)
            .map(dep -> toPurl(dep, "\\s{1,3}"))
            .collect(Collectors.toList());
    return ignored;
  }

  private String extractPackageName(String line) {
    String trimmedRow = line.trim();
    int firstRemarkNotationOccurrence = trimmedRow.indexOf("//");
    return trimmedRow.substring(0, firstRemarkNotationOccurrence).trim();
  }

  public boolean IgnoredLine(String line) {
    boolean result = false;
    if (IgnorePatternDetector.containsIgnorePattern(line)) {
      // if exhortignore or trustify-da-ignore is alone in a comment or is in a comment together
      // with indirect or as a
      // comment inside a
      // comment ( e.g // indirect  //exhort)
      // then this line is to be checked if it's a comment after a package name.
      if (Pattern.matches(".+//\\s*(exhortignore|trustify-da-ignore)", line)
          || Pattern.matches(".+//\\sindirect (//)?\\s*(exhortignore|trustify-da-ignore)", line)) {
        String trimmedRow = line.trim();
        // filter out lines where exhortignore or trustify-da-ignore has no meaning
        if (!trimmedRow.startsWith("module ")
            && !trimmedRow.startsWith("go ")
            && !trimmedRow.startsWith("require (")
            && !trimmedRow.startsWith("require(")
            && !trimmedRow.startsWith("exclude ")
            && !trimmedRow.startsWith("replace ")
            && !trimmedRow.startsWith("retract ")
            && !trimmedRow.startsWith("use ")
            && !trimmedRow.contains(
                "=>")) { // only for lines that after trimming starts with "require " or starting
          // with
          // package name followd by one space, and then a semver version.
          if (trimmedRow.startsWith("require ")
              || Pattern.matches(
                  "^[a-z.0-9/-]+\\s{1,2}[vV][0-9]\\.[0-9](\\.[0-9]){0,2}.*", trimmedRow)) {
            result = true;
          }
        }
      }
    }
    return result;
  }

  private static String getParentVertex(String edge) {
    String[] edgeParts = edge.trim().split(" ");
    return edgeParts[0];
  }

  private static String getChildVertex(String edge) {

    String[] edgeParts = edge.trim().split(" ");
    return edgeParts[1];
  }

  private static String getDefaultMainModuleVersion() {
    return DEFAULT_MAIN_VERSION;
  }
}
