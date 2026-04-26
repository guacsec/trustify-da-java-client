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
package io.github.guacsec.trustifyda.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;

/**
 * Shared utilities for Python providers that use {@code pyproject.toml} manifests. Provides TOML
 * parsing, ignore-pattern collection, and metadata extraction used by both {@code
 * PythonPyprojectProvider} and {@code PythonUvProvider}.
 */
public final class PyprojectTomlUtils {

  private PyprojectTomlUtils() {}

  /** Parses a {@code pyproject.toml} file and returns the result. */
  public static TomlParseResult parseToml(Path manifest) throws IOException {
    TomlParseResult parsed = Toml.parse(manifest);
    if (parsed.hasErrors()) {
      throw new IOException(
          "Invalid pyproject.toml format: " + parsed.errors().get(0).getMessage());
    }
    return parsed;
  }

  /**
   * Collects dependency identifiers marked with ignore patterns ({@code #exhortignore} or {@code
   * #trustify-da-ignore}) in the {@code [project.dependencies]} section.
   *
   * @param manifest the path to the pyproject.toml file
   * @param toml the parsed TOML result
   * @return set of raw dependency strings that are marked as ignored
   */
  public static Set<String> collectIgnoredDeps(Path manifest, TomlParseResult toml)
      throws IOException {
    List<String> rawLines = Files.readAllLines(manifest);
    Set<String> ignored = new HashSet<>();

    TomlArray projectDeps = toml.getArray("project.dependencies");
    if (projectDeps != null) {
      for (int i = 0; i < projectDeps.size(); i++) {
        String dep = projectDeps.getString(i);
        for (String line : rawLines) {
          if (line.contains(dep) && IgnorePatternDetector.containsIgnorePattern(line)) {
            ignored.add(dep);
            break;
          }
        }
      }
    }
    return ignored;
  }

  /** Reads {@code project.name} from a parsed pyproject.toml, or {@code null} if absent. */
  public static String getProjectName(TomlParseResult toml) {
    String name = toml.getString("project.name");
    return (name != null && !name.isBlank()) ? name : null;
  }

  /** Reads {@code project.version} from a parsed pyproject.toml, or {@code null} if absent. */
  public static String getProjectVersion(TomlParseResult toml) {
    String version = toml.getString("project.version");
    return (version != null && !version.isBlank()) ? version : null;
  }

  /**
   * Reads the license from a parsed pyproject.toml. Checks {@code project.license} first, then
   * {@code project.license.text} (PEP 639).
   *
   * @return the license string, or {@code null} if not found
   */
  public static String getLicense(TomlParseResult toml) {
    String license = toml.getString("project.license");
    if (license != null && !license.isBlank()) {
      return license;
    }
    String licenseText = toml.getString("project.license.text");
    return (licenseText != null && !licenseText.isBlank()) ? licenseText : null;
  }

  /** Returns {@code true} if the manifest contains {@code [tool.poetry.dependencies]}. */
  public static boolean hasPoetryDependencies(TomlParseResult toml) {
    return toml.getTable("tool.poetry.dependencies") != null;
  }

  /** Reads {@code tool.poetry.name} from a parsed pyproject.toml, or {@code null} if absent. */
  public static String getPoetryProjectName(TomlParseResult toml) {
    String name = toml.getString("tool.poetry.name");
    return (name != null && !name.isBlank()) ? name : null;
  }

  /** Reads {@code tool.poetry.version} from a parsed pyproject.toml, or {@code null} if absent. */
  public static String getPoetryProjectVersion(TomlParseResult toml) {
    String version = toml.getString("tool.poetry.version");
    return (version != null && !version.isBlank()) ? version : null;
  }

  /**
   * Canonicalizes a Python package name by lower-casing it and collapsing runs of hyphens,
   * underscores, and dots into a single hyphen, per PEP 503.
   */
  public static String canonicalize(String name) {
    return name.toLowerCase().replaceAll("[-_.]+", "-");
  }

  /**
   * Returns {@code true} if the directory contains a {@code pyproject.toml} with a {@code
   * [tool.uv.workspace]} section, indicating a uv workspace root.
   */
  public static boolean isUvWorkspaceRoot(Path dir) {
    Path pyprojectPath = dir.resolve("pyproject.toml");
    if (!Files.isRegularFile(pyprojectPath)) {
      return false;
    }
    try {
      TomlParseResult toml = Toml.parse(pyprojectPath);
      return toml.getTable("tool.uv.workspace") != null;
    } catch (Exception e) {
      return false;
    }
  }
}
