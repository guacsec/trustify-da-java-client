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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Concrete implementation of the {@link Provider} used for converting dependency trees for Java
 * Maven projects (pom.xml) into a content Dot Graphs for Stack analysis or Json for Component
 * analysis.
 */
public final class JavaMavenProvider extends BaseJavaProvider {

  private static final String PROP_JAVA_HOME = "JAVA_HOME";
  private static final Logger log = LoggersFactory.getLogger(JavaMavenProvider.class.getName());
  private final String mvnExecutable;
  private static final String MVN = Operations.isWindows() ? "mvn.cmd" : "mvn";
  private static final String ARG_VERSION = "-v";

  public JavaMavenProvider(Path manifest) {
    super(Type.MAVEN, manifest);
    // check for custom mvn executable mvn or mvn wrapper
    this.mvnExecutable = selectMvnRuntime(manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    var mvnCleanCmd = buildMvnCommandArgs("clean", "-f", manifest.toString(), "--batch-mode", "-q");
    var mvnEnvs = getMvnExecEnvs();
    // execute the clean command
    Operations.runProcess(manifest.getParent(), mvnCleanCmd.toArray(String[]::new), mvnEnvs);
    // create a temp file for storing the dependency tree in
    var tmpFile = Files.createTempFile("TRUSTIFY_DA_dot_graph_", null);
    // the tree command will build the project and create the dependency tree in the temp file
    var mvnTreeCmd =
        buildMvnCommandArgs(
            "org.apache.maven.plugins:maven-dependency-plugin:3.6.0:tree",
            "-Dverbose",
            "-DoutputType=text",
            String.format("-DoutputFile=%s", tmpFile.toString()),
            "-f",
            manifest.toString(),
            "--batch-mode",
            "-q");
    // if we have dependencies marked as ignored, exclude them from the tree command
    var ignored =
        getDependencies(manifest).stream()
            .filter(d -> d.ignored)
            .map(DependencyAggregator::toPurl)
            .map(PackageURL::getCoordinates)
            .collect(Collectors.toList());
    // execute the tree command
    Operations.runProcess(manifest.getParent(), mvnTreeCmd.toArray(String[]::new), mvnEnvs);
    if (debugLoggingIsNeeded()) {
      String stackAnalysisDependencyTree = Files.readString(tmpFile);
      log.info(
          String.format(
              "Package Manager Maven Stack Analysis Dependency Tree Output: %s %s",
              System.lineSeparator(), stackAnalysisDependencyTree));
    }

    var sbom = buildSbomFromTextFormat(tmpFile);
    // build and return content for constructing request to the backend
    return new Content(
        sbom.filterIgnoredDeps(ignored).getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private Sbom buildSbomFromTextFormat(Path textFormatFile) throws IOException {
    var sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    List<String> lines = Files.readAllLines(textFormatFile);
    var root = lines.get(0);
    var rootPurl = parseDep(root);
    sbom.addRoot(rootPurl);
    lines.remove(0);
    String[] array = new String[lines.size()];
    lines.toArray(array);
    //    createSbomIteratively(lines,sbom);
    parseDependencyTree(root, 0, array, sbom, null);
    return sbom;
  }

  @Override
  public Content provideComponent() throws IOException {
    // build effective pom command
    return generateSbomFromEffectivePom();
  }

  private Content generateSbomFromEffectivePom() throws IOException {
    var tmpEffPom = Files.createTempFile("TRUSTIFY_DA_eff_pom_", ".xml");
    var mvnEffPomCmd =
        buildMvnCommandArgs(
            "clean",
            "help:effective-pom",
            String.format("-Doutput=%s", tmpEffPom.toString()),
            "-f",
            manifest.toString(),
            "--batch-mode",
            "-q");
    // execute the effective pom command
    Operations.runProcess(
        manifest.getParent(), mvnEffPomCmd.toArray(String[]::new), getMvnExecEnvs());
    if (debugLoggingIsNeeded()) {
      String CaEffectivePoM = Files.readString(tmpEffPom);
      log.info(
          String.format(
              "Package Manager Maven Component Analysis Effective POM Output : %s %s",
              System.lineSeparator(), CaEffectivePoM));
    }
    // if we have dependencies marked as ignored grab ignored dependencies from the original pom
    // the effective-pom goal doesn't carry comments
    List<DependencyAggregator> dependencies = getDependencies(manifest);
    var ignored =
        dependencies.stream()
            .filter(d -> d.ignored)
            .map(DependencyAggregator::toPurl)
            .collect(Collectors.toSet());
    var testsDeps =
        dependencies.stream()
            .filter(DependencyAggregator::isTestDependency)
            .collect(Collectors.toSet());
    var deps = getDependencies(tmpEffPom);
    var sbom = SbomFactory.newInstance().addRoot(getRoot(tmpEffPom));
    deps.stream()
        .filter(dep -> !testsDeps.contains(dep))
        .map(DependencyAggregator::toPurl)
        .filter(dep -> ignored.stream().noneMatch(artifact -> artifact.isCoordinatesEquals(dep)))
        .forEach(d -> sbom.addDependency(sbom.getRoot(), d, null));

    // build and return content for constructing request to the backend
    return new Content(sbom.getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private PackageURL getRoot(final Path manifestPath) throws IOException {
    XMLStreamReader reader = null;
    try {
      reader =
          XMLInputFactory.newInstance().createXMLStreamReader(Files.newInputStream(manifestPath));
      DependencyAggregator dependencyAggregator = null;
      boolean isRoot = false;
      while (reader.hasNext()) {
        reader.next(); // get the next event
        if (reader.isStartElement() && "project".equals(reader.getLocalName())) {
          isRoot = true;
          dependencyAggregator = new DependencyAggregator();
          continue;
        }
        if (!Objects.isNull(dependencyAggregator)) {
          if (reader.isStartElement()) {
            switch (reader.getLocalName()) {
              case "groupId": // starting "groupId" tag, get next event and set to aggregator
                reader.next();
                dependencyAggregator.groupId = reader.getText();
                break;
              case "artifactId": // starting "artifactId" tag, get next event and set to aggregator
                reader.next();
                dependencyAggregator.artifactId = reader.getText();
                break;
              case "version": // starting "version" tag, get next event and set to aggregator
                reader.next();
                dependencyAggregator.version = reader.getText();
                break;
            }
          }
          if (dependencyAggregator.isValid()) {
            return dependencyAggregator.toPurl();
          }
        }
      }
    } catch (XMLStreamException exc) {
      throw new IOException(exc);
    } finally {
      if (!Objects.isNull(reader)) {
        try {
          reader.close(); // close stream if open
        } catch (XMLStreamException e) {
          //
        }
      }
    }

    throw new IllegalStateException("Unable to retrieve Root dependency from effective pom");
  }

  private List<DependencyAggregator> getDependencies(final Path manifestPath) throws IOException {
    List<DependencyAggregator> deps = new ArrayList<>();
    XMLStreamReader reader = null;
    try {
      // get a xml stream reader for the manifest file
      reader =
          XMLInputFactory.newInstance().createXMLStreamReader(Files.newInputStream(manifestPath));
      // the following dependencyIgnore object is used to aggregate dependency data over iterations
      // when a "dependency" tag starts, it will be initiated,
      // when a "dependency" tag ends, it will be parsed, act upon, and reset
      DependencyAggregator dependencyAggregator = null;
      boolean insideDependencyManagement = false;
      boolean insideExclusions = false;
      boolean insidePlugins = false;
      while (reader.hasNext()) {
        reader.next(); // get the next event
        if (reader.isStartElement() && "dependencyManagement".equals(reader.getLocalName())) {
          insideDependencyManagement = true;
          continue;
        }
        if (reader.isEndElement() && "dependencyManagement".equals(reader.getLocalName())) {
          insideDependencyManagement = false;
          continue;
        }
        if (reader.isStartElement() && "plugins".equals(reader.getLocalName())) {
          insidePlugins = true;
          continue;
        }
        if (reader.isEndElement() && "plugins".equals(reader.getLocalName())) {
          insidePlugins = false;
          continue;
        }
        if (reader.isStartElement() && "exclusions".equals(reader.getLocalName())) {
          insideExclusions = true;
          continue;
        }
        if (reader.isEndElement() && "exclusions".equals(reader.getLocalName())) {
          insideExclusions = false;
          continue;
        }
        if (reader.isStartElement() && "dependency".equals(reader.getLocalName())) {
          // starting "dependency" tag, initiate aggregator only if not inside dependencyManagement
          // or plugins
          if (!insideDependencyManagement && !insidePlugins) {
            dependencyAggregator = new DependencyAggregator();
          }
          continue;
        }

        // if dependency aggregator haven't been initiated,
        // we're currently not iterating over a "dependency" tag - no need for further parsing
        if (!Objects.isNull(dependencyAggregator)) {
          // if we hit an ignore comment, mark aggregator to be ignored
          if (reader.getEventType() == XMLStreamConstants.COMMENT
              && isIgnoreComment(reader.getText())) {
            dependencyAggregator.ignored = true;
            continue;
          }

          if (reader.isStartElement() && !insideExclusions) {
            // NOTE if we want to include "scope" tags in ignore,
            // add a case here and a property in DependencyIgnore
            // Only process these elements if we're not inside exclusions
            switch (reader.getLocalName()) {
              case "groupId": // starting "groupId" tag, get next event and set to aggregator
                reader.next();
                dependencyAggregator.groupId = reader.getText();
                break;
              case "artifactId": // starting "artifactId" tag, get next event and set to aggregator
                reader.next();
                dependencyAggregator.artifactId = reader.getText();
                break;

              case "scope":
                reader.next();
                dependencyAggregator.scope =
                    reader.getText() != null ? reader.getText().trim() : "*";
                break;
              case "version": // starting "version" tag, get next event and set to aggregator
                reader.next();
                dependencyAggregator.version = reader.getText();
                break;
            }
          }

          if (reader.isEndElement() && "dependency".equals(reader.getLocalName())) {
            // add object to list and reset dependency aggregator only if not inside
            // dependencyManagement or plugins
            if (!insideDependencyManagement && !insidePlugins && dependencyAggregator != null) {
              deps.add(dependencyAggregator);
            }
            dependencyAggregator = null;
          }
        }
      }
    } catch (XMLStreamException exc) {
      throw new IOException(exc);
    } finally {
      if (!Objects.isNull(reader)) {
        try {
          reader.close(); // close stream if open
        } catch (XMLStreamException e) {
          //
        }
      }
    }

    return deps;
  }

  Map<String, String> getMvnExecEnvs() {
    var javaHome = Environment.get(PROP_JAVA_HOME);
    if (javaHome != null && !javaHome.isBlank()) {
      return Collections.singletonMap(PROP_JAVA_HOME, javaHome);
    }
    return null;
  }

  private List<String> buildMvnCommandArgs(String... baseArgs) {
    List<String> args = new ArrayList<>();
    args.add(mvnExecutable);

    var userSettingsFile = Operations.getMavenConfig("USER_SETTINGS");
    if (userSettingsFile != null) {
      args.add("-s");
      args.add(userSettingsFile);
    }

    var localRepository = Operations.getMavenConfig("LOCAL_REPO");
    if (localRepository != null) {
      args.add("-Dmaven.repo.local=" + localRepository);
    }

    for (String arg : baseArgs) {
      args.add(arg);
    }

    return args;
  }

  // NOTE if we want to include "scope" tags in ignore,
  // add property here and a case in the start-element-switch in the getIgnored method

  /** Aggregator class for aggregating Dependency data over stream iterations, * */
  private static final class DependencyAggregator {
    private String scope = "*";
    private String groupId;
    private String artifactId;
    private String version;
    boolean ignored = false;

    /**
     * Get the string representation of the dependency to use as excludes
     *
     * @return an exclude string for the dependency:tree plugin, i.e. group-id:artifact-id:*:version
     */
    @Override
    public String toString() {
      // NOTE if you add scope, don't forget to replace the * with its value
      return String.format("%s:%s:%s:%s", groupId, artifactId, scope, version);
    }

    public boolean isValid() {
      return Objects.nonNull(groupId) && Objects.nonNull(artifactId) && Objects.nonNull(version);
    }

    public boolean isTestDependency() {
      return scope.trim().equals("test");
    }

    public PackageURL toPurl() {
      try {
        return new PackageURL(
            Type.MAVEN.getType(),
            groupId,
            artifactId,
            version,
            this.scope.equals("*") ? null : new TreeMap<>(Map.of("scope", this.scope)),
            null);
      } catch (MalformedPackageURLException e) {
        throw new IllegalArgumentException("Unable to parse PackageURL", e);
      }
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof DependencyAggregator)) return false;
      var that = (DependencyAggregator) o;
      // NOTE we do not compare the ignored field
      // This is required for comparing pom.xml with effective_pom.xml as the latter doesn't
      // contain comments indicating ignore
      return Objects.equals(this.groupId, that.groupId)
          && Objects.equals(this.artifactId, that.artifactId)
          && Objects.equals(this.version, that.version);
    }

    @Override
    public int hashCode() {
      return Objects.hash(groupId, artifactId, version);
    }
  }

  private String selectMvnRuntime(final Path manifestPath) {
    boolean preferWrapper = Operations.getWrapperPreference(MVN);
    if (preferWrapper && manifestPath != null) {
      String wrapperName = Operations.isWindows() ? "mvnw.cmd" : "mvnw";
      String mvnw = traverseForMvnw(wrapperName, manifestPath.toString());
      if (mvnw != null) {
        try {
          // verify maven wrapper is accessible
          Operations.runProcess(manifest.getParent(), mvnw, ARG_VERSION);
          if (debugLoggingIsNeeded()) {
            log.info(String.format("using maven wrapper from : %s", mvnw));
          }
          return mvnw;
        } catch (Exception e) {
          log.log(
              Level.WARNING,
              "Failed to check for mvnw due to: {0} Fall back to use mvn",
              e.getMessage());
        }
      }
    }
    // If maven wrapper is not requested or not accessible, fall back to use mvn
    String mvn = Operations.getExecutable(MVN, ARG_VERSION);
    if (debugLoggingIsNeeded()) {
      log.info(String.format("using mvn executable from : %s", mvn));
    }
    return mvn;
  }

  private String traverseForMvnw(String wrapperName, String startingManifest) {
    return traverseForMvnw(wrapperName, startingManifest, null);
  }

  public static String traverseForMvnw(
      String wrapperName, String startingManifest, String repoRoot) {
    String normalizedManifest = normalizePath(startingManifest);

    Path path = Paths.get(normalizedManifest);
    if (repoRoot == null) {
      repoRoot =
          Operations.getGitRootDir(path.getParent().toString())
              .orElse(path.toAbsolutePath().getRoot().toString());
    }

    Path wrapperPath = path.getParent().resolve(wrapperName).toAbsolutePath();

    if (Files.isExecutable(wrapperPath)) {
      return wrapperPath.toString();
    } else {
      String currentDir = path.getParent().toAbsolutePath().toString();
      if (currentDir.equals(repoRoot)) {
        return null;
      }
      return traverseForMvnw(wrapperName, path.getParent().toString(), repoRoot);
    }
  }

  public static String normalizePath(String thePath) {
    Path normalized = Paths.get(thePath).toAbsolutePath().normalize();
    String result = normalized.toString();
    if (Operations.isWindows()) {
      result = result.toLowerCase();
    }
    return result;
  }

  /**
   * Checks if a comment text exactly matches an ignore pattern. Used for XML comment detection in
   * pom.xml files.
   *
   * @param commentText the comment text to check (will be stripped of whitespace)
   * @return true if the comment exactly matches an ignore pattern
   */
  private boolean isIgnoreComment(String commentText) {
    String stripped = commentText.strip();
    return IgnorePatternDetector.IGNORE_PATTERN.equals(stripped)
        || IgnorePatternDetector.LEGACY_IGNORE_PATTERN.equals(stripped);
  }
}
