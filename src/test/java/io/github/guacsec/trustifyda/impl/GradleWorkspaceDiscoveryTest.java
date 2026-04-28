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
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class GradleWorkspaceDiscoveryTest {

  private static final Path GRADLE_FIXTURES =
      Path.of("src/test/resources/tst_manifests/workspace/gradle");

  // --- parseGradleInitScriptOutput tests (pure function, no mocking needed) ---

  @Test
  void parseGradleInitScriptOutput_standardOutput() {
    String raw =
        "::DA_PROJECT::::/home/project\n"
            + "::DA_PROJECT:::app::/home/project/app\n"
            + "::DA_PROJECT:::lib::/home/project/lib\n";

    List<ExhortApi.GradleProject> result = ExhortApi.parseGradleInitScriptOutput(raw);

    assertThat(result).hasSize(3);
    assertThat(result.get(0).path()).isEqualTo(":");
    assertThat(result.get(0).dir()).isEqualTo("/home/project");
    assertThat(result.get(1).path()).isEqualTo(":app");
    assertThat(result.get(1).dir()).isEqualTo("/home/project/app");
  }

  @Test
  void parseGradleInitScriptOutput_nestedProjects() {
    String raw =
        "::DA_PROJECT::::/home/project\n"
            + "::DA_PROJECT:::libs:core::/home/project/libs/core\n"
            + "::DA_PROJECT:::libs:util::/home/project/libs/util\n";

    List<ExhortApi.GradleProject> result = ExhortApi.parseGradleInitScriptOutput(raw);

    assertThat(result).hasSize(3);
    assertThat(result.get(1).path()).isEqualTo(":libs:core");
    assertThat(result.get(1).dir()).isEqualTo("/home/project/libs/core");
  }

  @Test
  void parseGradleInitScriptOutput_nullInput() {
    assertThat(ExhortApi.parseGradleInitScriptOutput(null)).isEmpty();
  }

  @Test
  void parseGradleInitScriptOutput_emptyInput() {
    assertThat(ExhortApi.parseGradleInitScriptOutput("")).isEmpty();
  }

  @Test
  void parseGradleInitScriptOutput_ignoresNonPrefixedLines() {
    String raw = "some gradle log output\n::DA_PROJECT:::app::/home/project/app\nmore output\n";

    List<ExhortApi.GradleProject> result = ExhortApi.parseGradleInitScriptOutput(raw);

    assertThat(result).hasSize(1);
    assertThat(result.getFirst().path()).isEqualTo(":app");
  }

  // --- discoverWorkspaceManifests tests (require mocking Operations) ---

  @Test
  void discoverWorkspaceManifests_gradleMultiProject() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_multi_project").toAbsolutePath().normalize();

    String initScriptOutput =
        "::DA_PROJECT::::"
            + workspaceDir
            + "\n"
            + "::DA_PROJECT:::app::"
            + workspaceDir.resolve("app")
            + "\n"
            + "::DA_PROJECT:::lib::"
            + workspaceDir.resolve("lib")
            + "\n";

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput(initScriptOutput, "", 0));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(3);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("build.gradle"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().contains("app" + File.separator + "build.gradle"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().contains("lib" + File.separator + "build.gradle"));
    }
  }

  @Test
  void discoverWorkspaceManifests_nestedSubprojects() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_nested_subprojects").toAbsolutePath().normalize();

    String initScriptOutput =
        "::DA_PROJECT::::"
            + workspaceDir
            + "\n"
            + "::DA_PROJECT:::libs:core::"
            + workspaceDir.resolve("libs/core")
            + "\n"
            + "::DA_PROJECT:::libs:util::"
            + workspaceDir.resolve("libs/util")
            + "\n";

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput(initScriptOutput, "", 0));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(3);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("build.gradle"));
      assertThat(manifests)
          .anyMatch(
              p ->
                  p.toString()
                      .contains(
                          "libs" + File.separator + "core" + File.separator + "build.gradle"));
      assertThat(manifests)
          .anyMatch(
              p ->
                  p.toString()
                      .contains(
                          "libs" + File.separator + "util" + File.separator + "build.gradle"));
    }
  }

  @Test
  void discoverWorkspaceManifests_mixedGroovyAndKotlin() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_mixed_variants").toAbsolutePath().normalize();

    String initScriptOutput =
        "::DA_PROJECT::::"
            + workspaceDir
            + "\n"
            + "::DA_PROJECT:::app::"
            + workspaceDir.resolve("app")
            + "\n"
            + "::DA_PROJECT:::lib::"
            + workspaceDir.resolve("lib")
            + "\n";

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput(initScriptOutput, "", 0));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(3);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("build.gradle.kts"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().endsWith("app" + File.separator + "build.gradle"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().endsWith("lib" + File.separator + "build.gradle.kts"));
    }
  }

  @Test
  void discoverWorkspaceManifests_noSubprojects() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_no_subprojects").toAbsolutePath().normalize();

    String initScriptOutput = "::DA_PROJECT::::" + workspaceDir + "\n";

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput(initScriptOutput, "", 0));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("build.gradle"));
    }
  }

  @Test
  void discoverWorkspaceManifests_gradleCommandFails() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_multi_project").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("", "error", 1));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("build.gradle"));
    }
  }

  @Test
  void discoverWorkspaceManifests_missingSubprojectDirectory() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_missing_subproject").toAbsolutePath().normalize();

    String initScriptOutput =
        "::DA_PROJECT::::"
            + workspaceDir
            + "\n"
            + "::DA_PROJECT:::app::"
            + workspaceDir.resolve("app")
            + "\n"
            + "::DA_PROJECT:::lib-missing::"
            + workspaceDir.resolve("lib-missing")
            + "\n";

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput(initScriptOutput, "", 0));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(2);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("build.gradle"));
      assertThat(manifests).anyMatch(p -> p.toString().contains("app"));
      assertThat(manifests).noneMatch(p -> p.toString().contains("lib-missing"));
    }
  }

  @Test
  void discoverWorkspaceManifests_ignorePatternFiltering() throws IOException {
    Path workspaceDir =
        GRADLE_FIXTURES.resolve("gradle_multi_project").toAbsolutePath().normalize();

    String initScriptOutput =
        "::DA_PROJECT::::"
            + workspaceDir
            + "\n"
            + "::DA_PROJECT:::app::"
            + workspaceDir.resolve("app")
            + "\n"
            + "::DA_PROJECT:::lib::"
            + workspaceDir.resolve("lib")
            + "\n";

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("gradle")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput(initScriptOutput, "", 0));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of("**/lib/**"));

      assertThat(manifests).anyMatch(p -> p.toString().contains("app"));
      assertThat(manifests).noneMatch(p -> p.toString().contains("lib"));
    }
  }

  @Test
  void defaultIgnorePatterns_includesBuildAndGradle() {
    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    Set<String> resolvedPatterns = api.resolveIgnorePatterns(null);

    assertThat(resolvedPatterns).contains("**/build/**");
    assertThat(resolvedPatterns).contains("**/.gradle/**");
  }
}
