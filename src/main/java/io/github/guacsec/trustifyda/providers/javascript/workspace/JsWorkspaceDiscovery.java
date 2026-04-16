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
package io.github.guacsec.trustifyda.providers.javascript.workspace;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.utils.WorkspaceUtils;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Discovers JavaScript/TypeScript workspace member manifests from pnpm-workspace.yaml or
 * package.json workspaces configuration.
 */
public final class JsWorkspaceDiscovery {

  private static final Logger log = LoggersFactory.getLogger(JsWorkspaceDiscovery.class.getName());

  private static final String PNPM_WORKSPACE_YAML = "pnpm-workspace.yaml";
  private static final String PACKAGE_JSON = "package.json";
  private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
  private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

  private JsWorkspaceDiscovery() {}

  /**
   * Discovers workspace member package.json paths in the given workspace directory.
   *
   * <p>Checks for pnpm-workspace.yaml first, then falls back to package.json workspaces field. Each
   * discovered package.json is validated to ensure it has name and version fields.
   *
   * @param workspaceDir the workspace root directory
   * @param ignorePatterns glob patterns for paths to exclude from discovery
   * @return list of validated workspace member manifest paths
   * @throws IOException if reading workspace configuration files fails
   */
  public static List<Path> discoverWorkspaceManifests(Path workspaceDir, Set<String> ignorePatterns)
      throws IOException {
    List<String> workspaceGlobs = parseWorkspaceGlobs(workspaceDir);
    if (workspaceGlobs.isEmpty()) {
      return Collections.emptyList();
    }

    List<Path> manifests = findManifestsByGlobs(workspaceDir, workspaceGlobs);
    manifests = WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifests, ignorePatterns);
    manifests = validateManifests(manifests);
    return Collections.unmodifiableList(manifests);
  }

  /**
   * Checks whether the given directory is a JS workspace root by looking for pnpm-workspace.yaml or
   * a package.json with a workspaces field.
   *
   * @param dir the directory to check
   * @return true if the directory contains workspace configuration
   */
  public static boolean isWorkspaceRoot(Path dir) {
    if (Files.isRegularFile(dir.resolve(PNPM_WORKSPACE_YAML))) {
      return true;
    }
    Path packageJson = dir.resolve(PACKAGE_JSON);
    if (Files.isRegularFile(packageJson)) {
      try {
        JsonNode root = JSON_MAPPER.readTree(Files.newInputStream(packageJson));
        return root.has("workspaces");
      } catch (IOException e) {
        log.warning("Failed to read " + packageJson + ": " + e.getMessage());
      }
    }
    return false;
  }

  private static List<String> parseWorkspaceGlobs(Path workspaceDir) throws IOException {
    // Try pnpm-workspace.yaml first
    Path pnpmWorkspace = workspaceDir.resolve(PNPM_WORKSPACE_YAML);
    if (Files.isRegularFile(pnpmWorkspace)) {
      return parsePnpmWorkspaceYaml(pnpmWorkspace);
    }

    // Fall back to package.json workspaces field
    Path packageJson = workspaceDir.resolve(PACKAGE_JSON);
    if (Files.isRegularFile(packageJson)) {
      return parsePackageJsonWorkspaces(packageJson);
    }

    return Collections.emptyList();
  }

  /**
   * Parses pnpm-workspace.yaml and extracts the packages array.
   *
   * <p>Expected format:
   *
   * <pre>
   * packages:
   *   - "packages/*"
   *   - "apps/*"
   * </pre>
   */
  static List<String> parsePnpmWorkspaceYaml(Path yamlPath) throws IOException {
    JsonNode root = YAML_MAPPER.readTree(Files.newInputStream(yamlPath));
    JsonNode packages = root.get("packages");
    if (packages == null || !packages.isArray()) {
      return Collections.emptyList();
    }

    List<String> globs = new ArrayList<>();
    for (JsonNode entry : packages) {
      String pattern = entry.asText();
      if (pattern != null && !pattern.isBlank()) {
        globs.add(pattern);
      }
    }
    return globs;
  }

  /**
   * Parses package.json workspaces field, supporting both array and object formats.
   *
   * <p>Array format: {@code "workspaces": ["packages/*", "apps/*"]}
   *
   * <p>Object format: {@code "workspaces": {"packages": ["packages/*"]}}
   */
  static List<String> parsePackageJsonWorkspaces(Path packageJsonPath) throws IOException {
    JsonNode root = JSON_MAPPER.readTree(Files.newInputStream(packageJsonPath));
    JsonNode workspaces = root.get("workspaces");
    if (workspaces == null) {
      return Collections.emptyList();
    }

    if (workspaces.isArray()) {
      return extractArrayGlobs(workspaces);
    }

    if (workspaces.isObject()) {
      JsonNode packages = workspaces.get("packages");
      if (packages != null && packages.isArray()) {
        return extractArrayGlobs(packages);
      }
    }

    return Collections.emptyList();
  }

  private static List<String> extractArrayGlobs(JsonNode array) {
    List<String> globs = new ArrayList<>();
    for (JsonNode entry : array) {
      String pattern = entry.asText();
      if (pattern != null && !pattern.isBlank()) {
        globs.add(pattern);
      }
    }
    return globs;
  }

  private static List<Path> findManifestsByGlobs(Path workspaceDir, List<String> globs)
      throws IOException {
    List<Path> manifests = new ArrayList<>();

    for (String glob : globs) {
      // Normalize glob: remove trailing / if present
      String normalizedGlob = glob.endsWith("/") ? glob.substring(0, glob.length() - 1) : glob;

      // Build a PathMatcher for the directory pattern
      PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + normalizedGlob);

      Files.walkFileTree(
          workspaceDir,
          new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
              // Skip node_modules and hidden directories
              String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
              if (dirName.equals("node_modules") || dirName.startsWith(".")) {
                return FileVisitResult.SKIP_SUBTREE;
              }
              return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
              if (file.getFileName().toString().equals(PACKAGE_JSON)) {
                Path parent = workspaceDir.relativize(file.getParent());
                if (matcher.matches(parent)) {
                  manifests.add(file);
                }
              }
              return FileVisitResult.CONTINUE;
            }
          });
    }

    return manifests;
  }

  private static List<Path> validateManifests(List<Path> manifests) {
    List<Path> valid = new ArrayList<>();
    for (Path manifest : manifests) {
      try {
        JsonNode root = JSON_MAPPER.readTree(Files.newInputStream(manifest));
        JsonNode name = root.get("name");
        JsonNode version = root.get("version");
        if (name != null
            && name.isTextual()
            && !name.asText().isBlank()
            && version != null
            && version.isTextual()
            && !version.asText().isBlank()) {
          valid.add(manifest);
        } else {
          log.info("Skipping " + manifest + ": missing name or version");
        }
      } catch (IOException e) {
        log.warning("Skipping " + manifest + ": " + e.getMessage());
      }
    }
    return valid;
  }
}
