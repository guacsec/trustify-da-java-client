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
    String raw = "<strings>\n  <string>module-a</string>\n  <string>module-b</string>\n</strings>";
    List<String> result = ExhortApi.parseMavenModuleList(raw);
    assertThat(result).containsExactly("module-a", "module-b");
  }

  /** Verifies that a single module is parsed correctly. */
  @Test
  void parseMavenModuleList_singleModule() {
    String raw = "<strings>\n  <string>parent</string>\n</strings>";
    List<String> result = ExhortApi.parseMavenModuleList(raw);
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
    assertThat(ExhortApi.parseMavenModuleList("null")).isEmpty();
  }

  /** Verifies that a {@code <modules/>} tag returns an empty list. */
  @Test
  void parseMavenModuleList_emptyModulesTag() {
    assertThat(ExhortApi.parseMavenModuleList("<modules/>")).isEmpty();
  }

  /** Verifies that malformed XML returns an empty list. */
  @Test
  void parseMavenModuleList_malformedXml() {
    assertThat(ExhortApi.parseMavenModuleList("<strings><unclosed>")).isEmpty();
  }

  /** Verifies that non-XML input returns an empty list. */
  @Test
  void parseMavenModuleList_nonXmlInput() {
    assertThat(ExhortApi.parseMavenModuleList("module-a, module-b")).isEmpty();
  }

  /** Verifies that whitespace around module names is trimmed. */
  @Test
  void parseMavenModuleList_withWhitespace() {
    String raw =
        "<strings>\n  <string>  module-a  </string>\n  <string>  module-b  </string>\n</strings>";
    List<String> result = ExhortApi.parseMavenModuleList(raw);
    assertThat(result).containsExactly("module-a", "module-b");
  }

  // --- discoverWorkspaceManifests tests (require mocking Operations) ---

  /** Verifies that when mvn command fails, the root pom.xml is still returned. */
  @Test
  void discoverWorkspaceManifests_mvnCommandFails() throws IOException {
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getWrapperPreference("mvn")).thenReturn(false);
      mockOps.when(() -> Operations.isWindows()).thenReturn(false);
      mockOps.when(() -> Operations.getExecutable("mvn", "-v")).thenReturn("mvn");

      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("", "error", 1));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
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
      mockOps.when(() -> Operations.getExecutable("mvn", "-v")).thenReturn("mvn");

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
