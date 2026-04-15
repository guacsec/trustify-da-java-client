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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class JsWorkspaceDiscoveryTest {

  private static final Path WORKSPACE_FIXTURES =
      Path.of("src/test/resources/tst_manifests/workspace");

  /** Verifies that pnpm-workspace.yaml packages array is parsed and members are discovered. */
  @Test
  void testDiscoverFromPnpmWorkspaceYaml() throws IOException {
    // Given a workspace with pnpm-workspace.yaml
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("pnpm_workspace");

    // When discovering workspace manifests
    List<Path> manifests = JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, Set.of());

    // Then both packages are discovered
    assertThat(manifests).hasSize(2);
    assertThat(manifests)
        .extracting(p -> p.getParent().getFileName().toString())
        .containsExactlyInAnyOrder("pkg-a", "pkg-b");
  }

  /** Verifies that package.json workspaces array format is parsed correctly. */
  @Test
  void testDiscoverFromPackageJsonArrayFormat() throws IOException {
    // Given a workspace with package.json workspaces array
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("package_json_array");

    // When discovering workspace manifests
    List<Path> manifests = JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, Set.of());

    // Then both libraries are discovered
    assertThat(manifests).hasSize(2);
    assertThat(manifests)
        .extracting(p -> p.getParent().getFileName().toString())
        .containsExactlyInAnyOrder("lib-a", "lib-b");
  }

  /** Verifies that package.json workspaces object format with packages key is parsed. */
  @Test
  void testDiscoverFromPackageJsonObjectFormat() throws IOException {
    // Given a workspace with package.json workspaces object format
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("package_json_object");

    // When discovering workspace manifests
    List<Path> manifests = JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, Set.of());

    // Then the module is discovered
    assertThat(manifests).hasSize(1);
    assertThat(manifests)
        .extracting(p -> p.getParent().getFileName().toString())
        .containsExactly("mod-a");
  }

  /** Verifies that manifests missing name or version are skipped during validation. */
  @Test
  void testInvalidManifestsAreSkipped() throws IOException {
    // Given a workspace with some invalid package.json files
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("with_invalid");

    // When discovering workspace manifests
    List<Path> manifests = JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, Set.of());

    // Then only the valid package is included
    assertThat(manifests).hasSize(1);
    assertThat(manifests)
        .extracting(p -> p.getParent().getFileName().toString())
        .containsExactly("valid");
  }

  /** Verifies that an empty packages array in pnpm-workspace.yaml returns no manifests. */
  @Test
  void testEmptyWorkspaceReturnsEmpty() throws IOException {
    // Given a workspace with empty packages array
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("empty_workspace");

    // When discovering workspace manifests
    List<Path> manifests = JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, Set.of());

    // Then no manifests are found
    assertThat(manifests).isEmpty();
  }

  /** Verifies that ignore patterns filter out matching manifests. */
  @Test
  void testIgnorePatternsFilter() throws IOException {
    // Given a workspace with two packages and an ignore pattern for one
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("pnpm_workspace");

    // When discovering with an ignore pattern for pkg-b
    List<Path> manifests =
        JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, Set.of("packages/pkg-b"));

    // Then only pkg-a is returned
    assertThat(manifests).hasSize(1);
    assertThat(manifests)
        .extracting(p -> p.getParent().getFileName().toString())
        .containsExactly("pkg-a");
  }

  /** Verifies that isWorkspaceRoot detects a directory with pnpm-workspace.yaml. */
  @Test
  void testIsWorkspaceRootWithPnpmYaml() {
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("pnpm_workspace");
    assertThat(JsWorkspaceDiscovery.isWorkspaceRoot(workspaceDir)).isTrue();
  }

  /** Verifies that isWorkspaceRoot detects a directory with package.json workspaces field. */
  @Test
  void testIsWorkspaceRootWithPackageJsonWorkspaces() {
    Path workspaceDir = WORKSPACE_FIXTURES.resolve("package_json_array");
    assertThat(JsWorkspaceDiscovery.isWorkspaceRoot(workspaceDir)).isTrue();
  }

  /** Verifies that isWorkspaceRoot returns false for a regular package directory. */
  @Test
  void testIsWorkspaceRootReturnsFalseForRegularPackage() {
    Path packageDir = WORKSPACE_FIXTURES.resolve("pnpm_workspace/packages/pkg-a");
    assertThat(JsWorkspaceDiscovery.isWorkspaceRoot(packageDir)).isFalse();
  }

  /** Verifies that a directory with no workspace config returns empty results. */
  @Test
  void testNoWorkspaceConfigReturnsEmpty() throws IOException {
    // Given a directory with a plain package.json (no workspaces field)
    Path packageDir = WORKSPACE_FIXTURES.resolve("pnpm_workspace/packages/pkg-a");

    // When discovering workspace manifests
    List<Path> manifests = JsWorkspaceDiscovery.discoverWorkspaceManifests(packageDir, Set.of());

    // Then no manifests are found
    assertThat(manifests).isEmpty();
  }

  /** Verifies pnpm-workspace.yaml parsing extracts glob patterns. */
  @Test
  void testParsePnpmWorkspaceYaml() throws IOException {
    Path yamlPath = WORKSPACE_FIXTURES.resolve("pnpm_workspace/pnpm-workspace.yaml");
    List<String> globs = JsWorkspaceDiscovery.parsePnpmWorkspaceYaml(yamlPath);
    assertThat(globs).containsExactly("packages/*");
  }

  /** Verifies package.json workspaces parsing extracts glob patterns from array format. */
  @Test
  void testParsePackageJsonWorkspacesArray() throws IOException {
    Path packageJson = WORKSPACE_FIXTURES.resolve("package_json_array/package.json");
    List<String> globs = JsWorkspaceDiscovery.parsePackageJsonWorkspaces(packageJson);
    assertThat(globs).containsExactly("packages/*");
  }

  /** Verifies package.json workspaces parsing extracts glob patterns from object format. */
  @Test
  void testParsePackageJsonWorkspacesObject() throws IOException {
    Path packageJson = WORKSPACE_FIXTURES.resolve("package_json_object/package.json");
    List<String> globs = JsWorkspaceDiscovery.parsePackageJsonWorkspaces(packageJson);
    assertThat(globs).containsExactly("packages/*");
  }
}
