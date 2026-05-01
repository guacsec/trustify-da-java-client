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
package io.github.guacsec.trustifyda.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;

import io.github.guacsec.trustifyda.tools.Operations;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class MavenWorkspaceDiscoveryTest {

  private static final Path MAVEN_FIXTURES =
      Path.of("src/test/resources/tst_manifests/workspace/maven");

  // --- parseMavenModuleList tests (pure function, no mocking needed) ---

  /** Verifies that a standard module list output is parsed correctly. */
  @Test
  void parseMavenModuleList_standardOutput() {
    // Given a typical mvn help:evaluate output
    String raw = "[module-a, module-b]";

    // When parsing
    List<String> result = ExhortApi.parseMavenModuleList(raw);

    // Then both modules are returned
    assertThat(result).containsExactly("module-a", "module-b");
  }

  /** Verifies that a single module is parsed correctly. */
  @Test
  void parseMavenModuleList_singleModule() {
    // Given output with one module
    String raw = "[parent]";

    // When parsing
    List<String> result = ExhortApi.parseMavenModuleList(raw);

    // Then the single module is returned
    assertThat(result).containsExactly("parent");
  }

  /** Verifies that null input returns an empty list. */
  @Test
  void parseMavenModuleList_nullInput() {
    assertThat(ExhortApi.parseMavenModuleList(null)).isEmpty();
  }

  /** Verifies that empty string returns an empty list. */
  @Test
  void parseMavenModuleList_emptyInput() {
    assertThat(ExhortApi.parseMavenModuleList("")).isEmpty();
  }

  /** Verifies that 'null' string (no modules) returns an empty list. */
  @Test
  void parseMavenModuleList_nullString() {
    // "null" is returned by mvn when there are no modules
    assertThat(ExhortApi.parseMavenModuleList("null")).isEmpty();
  }

  /** Verifies that malformed output (no brackets) returns an empty list. */
  @Test
  void parseMavenModuleList_malformedOutput() {
    assertThat(ExhortApi.parseMavenModuleList("module-a, module-b")).isEmpty();
  }

  /** Verifies that whitespace around module names is trimmed. */
  @Test
  void parseMavenModuleList_withWhitespace() {
    // Given output with extra whitespace
    String raw = "[  module-a ,  module-b  ]";

    // When parsing
    List<String> result = ExhortApi.parseMavenModuleList(raw);

    // Then modules are trimmed
    assertThat(result).containsExactly("module-a", "module-b");
  }

  // --- discoverWorkspaceManifests tests (require mocking Operations) ---

  /** Verifies that a multi-module Maven project discovers all module pom.xml files. */
  @Test
  void discoverWorkspaceManifests_mavenMultiModule() throws IOException {
    // Given a multi-module Maven workspace
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      // Mock Maven binary resolution
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // Mock mvn help:evaluate for root pom -> returns [module-a, module-b]
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("[module-a, module-b]", "", 0));

      // Mock mvn help:evaluate for module-a -> returns null (leaf module)
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir.resolve("module-a")), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // Mock mvn help:evaluate for module-b -> returns null (leaf module)
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir.resolve("module-b")), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // When discovering workspace manifests
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      // Then root + 2 modules = 3 pom.xml files
      assertThat(manifests).hasSize(3);
      assertThat(manifests).allMatch(p -> p.getFileName().toString().equals("pom.xml"));
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
      assertThat(manifests).anyMatch(p -> p.toString().contains("module-a"));
      assertThat(manifests).anyMatch(p -> p.toString().contains("module-b"));
    }
  }

  /** Verifies that nested aggregator modules are discovered recursively. */
  @Test
  void discoverWorkspaceManifests_nestedAggregator() throws IOException {
    // Given a nested Maven aggregator workspace
    Path workspaceDir =
        MAVEN_FIXTURES.resolve("maven_nested_aggregator").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // Root -> [parent]
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("[parent]", "", 0));

      // parent -> [child]
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir.resolve("parent").toAbsolutePath().normalize()),
                      any(String[].class),
                      isNull()))
          .thenReturn(new Operations.ProcessExecOutput("[child]", "", 0));

      // child -> null (leaf)
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(
                          workspaceDir
                              .resolve("parent")
                              .resolve("child")
                              .toAbsolutePath()
                              .normalize()),
                      any(String[].class),
                      isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // When discovering workspace manifests
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      // Then root + parent + child = 3 pom.xml files
      assertThat(manifests).hasSize(3);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().contains("parent" + java.io.File.separator + "pom.xml"));
      assertThat(manifests)
          .anyMatch(
              p ->
                  p.toString()
                      .contains(
                          "parent"
                              + java.io.File.separator
                              + "child"
                              + java.io.File.separator
                              + "pom.xml"));
    }
  }

  /** Verifies that a project with no modules returns only the root pom.xml. */
  @Test
  void discoverWorkspaceManifests_noModules() throws IOException {
    // Given a Maven project with no modules
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_no_modules").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // Root -> null (no modules)
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // When discovering workspace manifests
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      // Then only the root pom.xml is returned
      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
    }
  }

  /** Verifies that missing module directories are skipped gracefully. */
  @Test
  void discoverWorkspaceManifests_missingModuleDirectory() throws IOException {
    // Given a Maven project where one module directory is missing
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_missing_module").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // Root -> [module-a, module-missing]
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("[module-a, module-missing]", "", 0));

      // module-a -> null (leaf)
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir.resolve("module-a").toAbsolutePath().normalize()),
                      any(String[].class),
                      isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // When discovering workspace manifests
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      // Then root + module-a = 2 (module-missing is skipped)
      assertThat(manifests).hasSize(2);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
      assertThat(manifests).anyMatch(p -> p.toString().contains("module-a"));
      assertThat(manifests).noneMatch(p -> p.toString().contains("module-missing"));
    }
  }

  /** Verifies that when mvn command fails, the root pom.xml is still returned. */
  @Test
  void discoverWorkspaceManifests_mvnCommandFails() throws IOException {
    // Given a Maven workspace where mvn invocation fails
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // mvn command fails with non-zero exit code
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("", "error", 1));

      // When discovering workspace manifests
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      // Then only the root pom.xml is returned (mvn failure falls through gracefully)
      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
    }
  }

  /** Verifies that ignore patterns filter out matched module paths. */
  @Test
  void discoverWorkspaceManifests_ignorePatternFiltering() throws IOException {
    // Given a multi-module Maven workspace with an ignore pattern
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // Root -> [module-a, module-b]
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("[module-a, module-b]", "", 0));

      // module-a -> null
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir.resolve("module-a").toAbsolutePath().normalize()),
                      any(String[].class),
                      isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // module-b -> null
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir.resolve("module-b").toAbsolutePath().normalize()),
                      any(String[].class),
                      isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // When discovering with ignore pattern for module-b
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of("**/module-b/**"));

      // Then module-b is filtered out
      assertThat(manifests).anyMatch(p -> p.toString().contains("module-a"));
      assertThat(manifests).noneMatch(p -> p.toString().contains("module-b"));
    }
  }

  /** Verifies that the default ignore patterns include target directories. */
  @Test
  void defaultIgnorePatterns_includesTarget() throws IOException {
    // Given a multi-module project with a pom in a target directory
    // The default patterns should include **/target/**
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("mvn")).thenReturn("mvn");

      // Root -> [module-a]
      mockOps
          .when(() -> Operations.runProcessGetFullOutput(any(), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("null", "", 0));

      // When resolving default ignore patterns
      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      Set<String> resolvedPatterns = api.resolveIgnorePatterns(null);

      // Then **/target/** is included
      assertThat(resolvedPatterns).contains("**/target/**");
      assertThat(resolvedPatterns).contains("**/node_modules/**");
      assertThat(resolvedPatterns).contains("**/.git/**");
    }
  }
}
