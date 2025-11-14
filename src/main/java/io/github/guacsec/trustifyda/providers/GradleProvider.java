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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.tomlj.Toml;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

/**
 * Concrete implementation of the {@link Provider} used for converting dependency trees for Gradle
 * projects (gradle.build / gradle.build.kts) into a content Dot Graphs for Stack analysis or Json
 * for Component analysis.
 */
public final class GradleProvider extends BaseJavaProvider {

  public static String RUNTIME_CLASSPATH = "runtimeClasspath";
  public static String COMPILE_CLASSPATH = "compileClasspath";
  public static String REQUIRED = "required";
  public static String OPTIONAL = "optional";

  private static final Logger log = LoggersFactory.getLogger(GradleProvider.class.getName());

  private final String gradleExecutable = Operations.getExecutable("gradle", "--version");

  public GradleProvider(Path manifest) {
    super(Type.GRADLE, manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    Path tempFile = getDependencies(manifest);
    if (debugLoggingIsNeeded()) {
      String stackAnalysisDependencyTree = Files.readString(tempFile);
      log.info(
          String.format(
              "Package Manager Gradle Stack Analysis Dependency Tree Output: %s %s",
              System.lineSeparator(), stackAnalysisDependencyTree));
    }
    Map<String, String> propertiesMap = extractProperties(manifest);

    var sbom = buildSbomFromTextFormat(tempFile, propertiesMap, AnalysisType.STACK);
    var ignored = getIgnoredDeps(manifest);

    return new Content(
        sbom.filterIgnoredDeps(ignored).getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private List<String> getIgnoredDeps(Path manifestPath) throws IOException {
    List<String> buildGradleLines = Files.readAllLines(manifestPath);
    List<String> ignored = new ArrayList<>();

    var ignoredLines =
        buildGradleLines.stream()
            .filter(this::isIgnoredLine)
            .map(this::extractPackageName)
            .collect(Collectors.toList());

    // Process each ignored dependency
    for (String dependency : ignoredLines) {
      String ignoredDepInfo;
      if (depHasLibsNotation(dependency)) {
        ignoredDepInfo = getDepFromNotation(dependency, manifestPath);
      } else {
        ignoredDepInfo = getDepInfo(dependency);
      }

      if (ignoredDepInfo != null) {
        ignored.add(ignoredDepInfo);
      }
    }

    return ignored;
  }

  private String getDepInfo(String dependencyLine) {
    // Check if the line contains "group:", "name:", and "version:"
    if (dependencyLine.contains("group:")
        && dependencyLine.contains("name:")
        && dependencyLine.contains("version:")) {
      Pattern pattern = Pattern.compile("(group|name|version):\\s*['\"](.*?)['\"]");
      Matcher matcher = pattern.matcher(dependencyLine);
      String groupId = null, artifactId = null, version = null;

      while (matcher.find()) {
        String key = matcher.group(1);
        String value = matcher.group(2);

        switch (key) {
          case "group":
            groupId = value;
            break;
          case "name":
            artifactId = value;
            break;
          case "version":
            version = value;
            break;
        }
      }
      if (groupId != null && artifactId != null && version != null) {
        PackageURL ignoredPackageUrl = toPurl(groupId, artifactId, version);
        return ignoredPackageUrl.getCoordinates();
      }
    } else {
      // Regular expression pattern to capture content inside single or double quotes
      Pattern pattern = Pattern.compile("['\"](.*?)['\"]");
      Matcher matcher = pattern.matcher(dependencyLine);
      // Check if the matcher finds a match
      if (matcher.find()) {
        // Get the matched string inside single or double quotes
        String dependency = matcher.group(1);
        String[] dependencyParts = dependency.split(":");
        if (dependencyParts.length == 3) {
          // Extract groupId, artifactId, and version
          String groupId = dependencyParts[0];
          String artifactId = dependencyParts[1];
          String version = dependencyParts[2];

          PackageURL ignoredPackageUrl = toPurl(groupId, artifactId, version);
          return ignoredPackageUrl.getCoordinates();
        }
      }
    }
    return null;
  }

  private String getDepFromNotation(String dependency, Path manifestPath) throws IOException {
    // Extract everything after "libs."
    String alias = dependency.substring(dependency.indexOf("libs.") + "libs.".length()).trim();
    alias = alias.replace(".", "-").replace(")", "");

    // Read and parse the TOML file
    TomlParseResult toml = Toml.parse(getLibsVersionsTomlPath(manifestPath));
    TomlTable librariesTable = toml.getTable("libraries");
    TomlTable dependencyTable = librariesTable.getTable(alias);
    if (dependencyTable != null) {
      String groupId = dependencyTable.getString("module").split(":")[0];
      String artifactId = dependencyTable.getString("module").split(":")[1];
      String version =
          toml.getTable("versions").getString(dependencyTable.getString("version.ref"));
      PackageURL ignoredPackageUrl = toPurl(groupId, artifactId, version);
      return ignoredPackageUrl.getCoordinates();
    }

    return null;
  }

  private Path getLibsVersionsTomlPath(Path manifestPath) {
    return manifestPath.getParent().resolve("gradle/libs.versions.toml");
  }

  public PackageURL toPurl(String groupId, String artifactId, String version) {
    try {
      return new PackageURL(Type.MAVEN.getType(), groupId, artifactId, version, null, null);
    } catch (MalformedPackageURLException e) {
      throw new IllegalArgumentException("Unable to parse PackageURL", e);
    }
  }

  private boolean depHasLibsNotation(String depToBeIgnored) {
    Pattern pattern = Pattern.compile(":");
    Matcher matcher = pattern.matcher(depToBeIgnored.trim());
    return (depToBeIgnored.trim().startsWith("library(") || depToBeIgnored.trim().contains("libs."))
        && (matcher.results().count() <= 1);
  }

  private boolean isIgnoredLine(String line) {
    return line.contains("exhortignore");
  }

  private String extractPackageName(String line) {
    String packageName = line.trim();
    // Extract the package name before the comment
    int commentIndex = packageName.indexOf("//");
    if (commentIndex != -1) {
      packageName = packageName.substring(0, commentIndex).trim();
    }
    // Remove any other trailing comments or spaces
    commentIndex = packageName.indexOf("/*");
    if (commentIndex != -1) {
      packageName = packageName.substring(0, commentIndex).trim();
    }
    return packageName;
  }

  private Path getDependencies(Path manifestPath) throws IOException {
    // create a temp file for storing the dependency tree in
    var tempFile = Files.createTempFile("TRUSTIFY_DA_graph_", null);
    // the command will create the dependency tree in the temp file
    String gradleCommand = gradleExecutable + " dependencies";

    String[] cmdList = gradleCommand.split("\\s+");
    String gradleOutput =
        Operations.runProcessGetOutput(Path.of(manifestPath.getParent().toString()), cmdList);
    Files.writeString(tempFile, gradleOutput);

    return tempFile;
  }

  private Path getProperties(Path manifestPath) throws IOException {
    Path propsTempFile = Files.createTempFile("propsfile", ".txt");
    String propCmd = gradleExecutable + " properties";
    String[] propCmdList = propCmd.split("\\s+");
    String properties =
        Operations.runProcessGetOutput(Path.of(manifestPath.getParent().toString()), propCmdList);
    // Create a temporary file
    Files.writeString(propsTempFile, properties);

    return propsTempFile;
  }

  /**
   * Builds a Software Bill of Materials (SBOM) from a text format file based on the specified
   * analysis type.
   *
   * <p>This method initializes an SBOM, extracts the root dependency, and processes runtime and
   * compile configuration lines from the provided text format file. Depending on the {@code
   * analysisType}:
   *
   * <ul>
   *   <li>For {@code AnalysisType.STACK}, it uses {@code prepareLinesForParsingDependencyTree} to
   *       prepare lines and parses the full dependency tree for both runtime (as {@code REQUIRED})
   *       and compile (as {@code OPTIONAL}) configurations.
   *   <li>For {@code AnalysisType.COMPONENT}, it uses {@code
   *       prepareLinesForParsingDirectDependency} to prepare lines, filters for lines with a depth
   *       of 1 using {@code ProcessedLine}, and parses the filtered dependencies for runtime (as
   *       {@code REQUIRED}) and compile (as {@code OPTIONAL}) configurations.
   * </ul>
   *
   * The resulting SBOM includes the root dependency and parsed dependencies with appropriate
   * scopes.
   *
   * @param textFormatFile the path to the text format file containing dependency information
   * @param propertiesMap a map of properties used to extract the root dependency
   * @param analysisType the type of analysis to perform ({@code STACK} or {@code COMPONENT})
   * @return the constructed {@code Sbom} object with parsed dependencies
   * @throws IOException if an I/O error occurs while reading the text format file
   */
  private Sbom buildSbomFromTextFormat(
      Path textFormatFile, Map<String, String> propertiesMap, AnalysisType analysisType)
      throws IOException {
    Sbom sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    String root = getRoot(textFormatFile, propertiesMap);

    PackageURL rootPurl = parseDep(root);
    sbom.addRoot(rootPurl);

    List<String> runtimeConfig = extractLines(textFormatFile, RUNTIME_CLASSPATH);
    List<String> compileConfig = extractLines(textFormatFile, COMPILE_CLASSPATH);

    if (analysisType == AnalysisType.STACK) {
      List<String> runtimePreparedLines = prepareLinesForParsingDependencyTree(runtimeConfig);
      List<String> compilePreparedLines = prepareLinesForParsingDependencyTree(compileConfig);

      parseDependencyTree(root, 0, runtimePreparedLines.toArray(new String[0]), sbom, REQUIRED);
      parseDependencyTree(root, 0, compilePreparedLines.toArray(new String[0]), sbom, OPTIONAL);

    } else {
      List<ProcessedLine> runtimePreparedLines =
          prepareLinesForParsingDirectDependency(runtimeConfig);
      List<ProcessedLine> compilePreparedLines =
          prepareLinesForParsingDirectDependency(compileConfig);

      List<String> runtimeArrayForSbom = new ArrayList<>();
      for (ProcessedLine line : runtimePreparedLines) {
        if (line.getDepth() == 1) {
          runtimeArrayForSbom.add(line.getLine());
        }
      }
      parseDependencyTree(root, 0, runtimeArrayForSbom.toArray(new String[0]), sbom, REQUIRED);

      List<String> compileArrayForSbom = new ArrayList<>();
      for (ProcessedLine line : compilePreparedLines) {
        if (line.getDepth() == 1) {
          compileArrayForSbom.add(line.getLine());
        }
      }
      parseDependencyTree(root, 0, compileArrayForSbom.toArray(new String[0]), sbom, OPTIONAL);
    }
    return sbom;
  }

  /**
   * A class representing a processed line of text with an associated indentation depth.
   *
   * <p>This class encapsulates a line of text and its corresponding depth level, typically used to
   * represent hierarchical or structured data such as dependencies. The class provides methods to
   * access the line and depth, and overrides the {@code toString} method to provide a meaningful
   * string representation.
   */
  static class ProcessedLine {
    /** The text content of the processed line. */
    public final String line;

    /** The indentation depth associated with the line. */
    public final int depth;

    /**
     * Constructs a new {@code ProcessedLine} with the specified line and depth.
     *
     * @param line the text content of the line
     * @param depth the indentation depth of the line
     */
    public ProcessedLine(String line, int depth) {
      this.line = line;
      this.depth = depth;
    }

    public String getLine() {
      return line;
    }

    public int getDepth() {
      return depth;
    }

    @Override
    public String toString() {
      return "Dependency{line='" + line + "', depth=" + depth + "}";
    }
  }

  /**
   * Prepares a list of strings for parsing direct dependencies by transforming and filtering lines
   * into {@code ProcessedLine} objects.
   *
   * <p>This method processes each input line, skipping empty lines or those ending with " FAILED".
   * For valid lines, it:
   *
   * <ul>
   *   <li>Calculates the indentation depth using {@code getIndentationLevel}.
   *   <li>Applies transformations to the line using {@code replaceLine}.
   *   <li>Checks if the transformed line contains a version using {@code containsVersion}.
   *   <li>If a version is present, creates a new {@code ProcessedLine} with the transformed line
   *       appended with ":compile" and the calculated depth, and adds it to the result list.
   * </ul>
   *
   * The resulting list contains only lines that meet the version criteria, encapsulated as {@code
   * ProcessedLine} objects.
   *
   * @param lines the list of input strings to process
   * @return a list of {@code ProcessedLine} objects representing valid, transformed lines with
   *     their indentation depths
   */
  private List<ProcessedLine> prepareLinesForParsingDirectDependency(List<String> lines) {
    List<ProcessedLine> result = new ArrayList<>();

    for (String line : lines) {
      if (line.trim().isEmpty() || line.endsWith(" FAILED")) {
        continue;
      }

      int depth = getIndentationLevel(line);

      line = replaceLine(line);
      if (containsVersion(line)) {
        result.add(new ProcessedLine(line + ":compile", depth));
      }
    }

    return result;
  }

  /**
   * Prepares a list of strings for parsing a dependency tree by transforming and filtering lines.
   *
   * <p>This method processes each input line, skipping empty lines or those ending with " FAILED".
   * For valid lines, it:
   *
   * <ul>
   *   <li>Applies transformations to the line using {@code replaceLine}.
   *   <li>Checks if the transformed line contains a version using {@code containsVersion}.
   *   <li>If a version is present, appends ":compile" to the line and adds it to the result list.
   * </ul>
   *
   * The resulting list contains only transformed lines that meet the version criteria, suitable for
   * dependency tree parsing.
   *
   * @param lines the list of input strings to process
   * @return a list of transformed strings, each appended with ":compile", representing valid
   *     dependency lines
   */
  private List<String> prepareLinesForParsingDependencyTree(List<String> lines) {
    List<String> result = new ArrayList<>();

    for (String line : lines) {
      if (line.trim().isEmpty() || line.endsWith(" FAILED")) {
        continue;
      }

      line = replaceLine(line);
      if (containsVersion(line)) {
        result.add(line + ":compile");
      }
    }

    return result;
  }

  /**
   * Processes a given line of text by applying a series of string replacements to standardize its
   * format.
   *
   * <p>This method performs multiple transformations on the input line, including:
   *
   * <ul>
   *   <li>Replacing triple dashes ("---") with a single dash ("-") and four spaces with two spaces.
   *   <li>Simplifying colon-separated patterns of the form ":X:Y -> Z" to ":X:Z".
   *   <li>Transforming colon-separated patterns of the form "X:Y:Z" to "X:Y:jar:Z".
   *   <li>Removing trailing annotations such as " (n)", " (c)", or " (*)".
   *   <li>Appending ":compile" to the end of the line.
   * </ul>
   *
   * The transformed line is then returned.
   *
   * @param line the input string to be processed
   * @return the transformed string after applying all replacements
   */
  private String replaceLine(String line) {
    line = line.replaceAll("---", "-").replaceAll("    ", "  ");
    line = line.replaceAll(":(.*):(.*) -> (.*)$", ":$1:$3");
    line = line.replaceAll("(.*):(.*):(.*)$", "$1:$2:jar:$3");
    line = line.replaceAll(" \\(n\\)$", "");
    line = line.replaceAll(" \\(c\\)$", "");
    line = line.replaceAll(" \\(\\*\\)", "");
    return line;
  }

  /**
   * Determines the indentation level of a given line of text based on specific patterns.
   *
   * <p>This method analyzes the input line to calculate its indentation level. If the line starts
   * with a '+' or '\', it is considered to have an indentation level of 1. Otherwise, it counts
   * occurrences of specific indentation patterns ("| " or " ") to determine the level. If no such
   * patterns are found, it returns -1; otherwise, it returns the count of patterns plus 1.
   *
   * @param line the input string to analyze for indentation
   * @return the indentation level of the line; returns 1 if the line starts with '+' or '\', the
   *     count of indentation patterns plus 1 if patterns are found, or -1 if no patterns are found
   */
  public int getIndentationLevel(String line) {
    if (line.matches("^[\\\\+].*")) {
      return 1;
    }

    Pattern pattern = Pattern.compile("\\| {4}| {5}");
    Matcher matcher = pattern.matcher(line);
    int count = 0;
    while (matcher.find()) {
      count++;
    }

    return count == 0 ? -1 : count + 1;
  }

  private boolean containsVersion(String line) {
    String lineStripped = line.replace("(n)", "").trim();
    Pattern pattern1 =
        Pattern.compile("\\W*[a-z0-9.-]+:[a-z0-9.-]+:[0-9]+[.][0-9]+(.[0-9]+)?(.*)?.*");
    Pattern pattern2 = Pattern.compile(".*version:\\s?(')?[0-9]+[.][0-9]+(.[0-9]+)?(')?");
    Matcher matcher1 = pattern1.matcher(lineStripped);
    Matcher matcher2 = pattern2.matcher(lineStripped);
    return (matcher1.find() || matcher2.find()) && !lineStripped.contains("libs.");
  }

  private String getRoot(Path textFormatFile, Map<String, String> propertiesMap)
      throws IOException {
    String group = propertiesMap.get("group");
    String version = propertiesMap.get("version");
    String rootName = extractRootProjectValue(textFormatFile);
    return group + ':' + rootName + ':' + "jar" + ':' + version;
  }

  private String extractRootProjectValue(Path inputFilePath) throws IOException {
    List<String> lines = Files.readAllLines(inputFilePath);
    for (String line : lines) {
      if (line.contains("Root project")) {
        Pattern pattern = Pattern.compile("Root project '(.+)'");
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
          return matcher.group(1);
        }
      }
    }
    return null;
  }

  private Map<String, String> extractProperties(Path manifestPath) throws IOException {
    Path propsTempFile = getProperties(manifestPath);
    String content = Files.readString(propsTempFile);
    // Define the regular expression pattern for key-value pairs
    Pattern pattern = Pattern.compile("([^:]+):\\s+(.+)");
    Matcher matcher = pattern.matcher(content);
    // Create a Map to store key-value pairs
    Map<String, String> keyValueMap = new HashMap<>();

    // Iterate through matches and add them to the map
    while (matcher.find()) {
      String key = matcher.group(1).trim();
      String value = matcher.group(2).trim();
      keyValueMap.put(key, value);
    }
    // Check if any key-value pairs were found
    if (!keyValueMap.isEmpty()) {
      return keyValueMap;
    } else {
      return Collections.emptyMap();
    }
  }

  private List<String> extractLines(Path inputFilePath, String startMarker) throws IOException {
    List<String> lines = Files.readAllLines(inputFilePath);
    List<String> extractedLines = new ArrayList<>();
    boolean startFound = false;

    for (String line : lines) {
      // If the start marker is found, set startFound to true
      if (line.startsWith(startMarker)) {
        startFound = true;
        continue; // Skip the line containing the startMarker
      }
      // If startFound is true and the line is not empty, add it to the extractedLines list
      if (startFound && !line.trim().isEmpty()) {
        extractedLines.add(line);
      }
      // If an empty line is encountered, break out of the loop
      if (startFound && line.trim().isEmpty()) {
        break;
      }
    }
    return extractedLines;
  }

  @Override
  public Content provideComponent() throws IOException {

    Path tempFile = getDependencies(manifest);
    Map<String, String> propertiesMap = extractProperties(manifest);

    Sbom sbom = buildSbomFromTextFormat(tempFile, propertiesMap, AnalysisType.COMPONENT);
    var ignored = getIgnoredDeps(manifest);

    return new Content(
        sbom.filterIgnoredDeps(ignored).getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }
}
