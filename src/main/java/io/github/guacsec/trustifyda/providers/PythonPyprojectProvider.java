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
import io.github.guacsec.trustifyda.utils.PythonControllerBase;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

public final class PythonPyprojectProvider extends PythonProvider {

  private Set<String> collectedIgnoredDeps;

  public PythonPyprojectProvider(Path manifest) {
    super(manifest);
  }

  @Override
  protected Path getRequirementsPath() throws IOException {
    List<String> depStrings = parseDependencyStrings();
    Path tmpDir = Files.createTempDirectory("trustify_da_pyproject_");
    Path tmpFile = Files.createFile(tmpDir.resolve("requirements.txt"));
    Files.write(tmpFile, depStrings);
    return tmpFile;
  }

  @Override
  protected void cleanupRequirementsPath(Path requirementsPath) throws IOException {
    Files.deleteIfExists(requirementsPath);
    Files.deleteIfExists(requirementsPath.getParent());
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

  List<String> parseDependencyStrings() throws IOException {
    TomlParseResult toml = Toml.parse(manifest);
    if (toml.hasErrors()) {
      throw new IOException("Invalid pyproject.toml format: " + toml.errors().get(0).getMessage());
    }

    List<String> rawLines = Files.readAllLines(manifest);
    collectedIgnoredDeps = new HashSet<>();
    List<String> deps = new ArrayList<>();

    // [project.dependencies] - PEP 621
    TomlArray projectDeps = toml.getArray("project.dependencies");
    if (projectDeps != null) {
      for (int i = 0; i < projectDeps.size(); i++) {
        String dep = projectDeps.getString(i);
        deps.add(dep);
        checkIgnored(rawLines, dep, dep);
      }
    }

    // [tool.poetry.dependencies] - production only
    TomlTable poetryDeps = toml.getTable("tool.poetry.dependencies");
    if (poetryDeps != null) {
      for (String name : poetryDeps.keySet()) {
        if (!"python".equalsIgnoreCase(name)) {
          deps.add(poetryDepToRequirement(name, poetryDeps, name));
          checkIgnored(rawLines, name, name);
        }
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

  /**
   * Converts a Poetry dependency entry to a pip-compatible requirement string. Poetry uses {@code
   * ^} and {@code ~} operators which are not PEP 440, so they must be converted to PEP 440 ranges.
   */
  static String poetryDepToRequirement(String name, TomlTable table, String key) {
    String version = null;
    if (table.isString(key)) {
      version = table.getString(key);
    } else if (table.isTable(key)) {
      TomlTable depTable = table.getTable(key);
      if (depTable != null) {
        version = depTable.getString("version");
      }
    }
    if (version == null || version.isEmpty() || "*".equals(version)) {
      return name;
    }
    return name + convertPoetryVersion(version);
  }

  /**
   * Converts a Poetry version constraint to PEP 440 format.
   *
   * <ul>
   *   <li>{@code ^X.Y.Z} → {@code >=X.Y.Z,<(X+1).0.0} (when X &gt; 0)
   *   <li>{@code ^0.Y.Z} → {@code >=0.Y.Z,<0.(Y+1).0} (when Y &gt; 0)
   *   <li>{@code ^0.0.Z} → {@code >=0.0.Z,<0.0.(Z+1)}
   *   <li>{@code ~X.Y.Z} → {@code >=X.Y.Z,<X.(Y+1).0}
   *   <li>PEP 440 operators ({@code >=}, {@code ==}, etc.) are passed through unchanged
   * </ul>
   */
  static String convertPoetryVersion(String version) {
    if (version.startsWith("^")) {
      return convertCaret(version.substring(1));
    }
    if (version.startsWith("~") && !version.startsWith("~=")) {
      return convertTilde(version.substring(1));
    }
    if (version.matches("^\\d.*")) {
      return "==" + version;
    }
    // Already PEP 440 compatible (>=, ==, ~=, !=, etc.)
    return version;
  }

  private static int parseNumericPart(String part) {
    return Integer.parseInt(part.replaceAll("[^0-9].*", ""));
  }

  private static String convertCaret(String ver) {
    String[] parts = ver.split("\\.");
    int major = parseNumericPart(parts[0]);
    int minor = parts.length > 1 ? parseNumericPart(parts[1]) : 0;
    int patch = parts.length > 2 ? parseNumericPart(parts[2]) : 0;
    String fullVer = major + "." + minor + "." + patch;

    if (major > 0) {
      return ">=" + fullVer + ",<" + (major + 1) + ".0.0";
    }
    if (minor > 0) {
      return ">=" + fullVer + ",<0." + (minor + 1) + ".0";
    }
    return ">=" + fullVer + ",<0.0." + (patch + 1);
  }

  private static String convertTilde(String ver) {
    String[] parts = ver.split("\\.");
    int major = parseNumericPart(parts[0]);
    int minor = parts.length > 1 ? parseNumericPart(parts[1]) : 0;
    int patch = parts.length > 2 ? parseNumericPart(parts[2]) : 0;
    String fullVer = major + "." + minor + "." + patch;
    return ">=" + fullVer + ",<" + major + "." + (minor + 1) + ".0";
  }
}
