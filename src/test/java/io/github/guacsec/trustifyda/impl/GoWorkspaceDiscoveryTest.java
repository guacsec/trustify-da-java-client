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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.guacsec.trustifyda.providers.golang.model.GoWorkspace;
import io.github.guacsec.trustifyda.tools.Operations;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class GoWorkspaceDiscoveryTest {

  private static final Path GO_FIXTURES = Path.of("src/test/resources/tst_manifests/workspace/go");

  private static final ObjectMapper MAPPER = new ObjectMapper();

  // --- GoWorkspace deserialization tests ---

  @Test
  void goWorkspace_deserializesStandardOutput() throws Exception {
    String json =
        """
        {
            "Go": "1.22",
            "Use": [
                {"DiskPath": "./module-a"},
                {"DiskPath": "./module-b"}
            ]
        }
        """;
    GoWorkspace workspace = MAPPER.readValue(json, GoWorkspace.class);

    assertThat(workspace.use()).hasSize(2);
    assertThat(workspace.use().getFirst().diskPath()).isEqualTo("./module-a");
    assertThat(workspace.use().get(1).diskPath()).isEqualTo("./module-b");
  }

  @Test
  void goWorkspace_handlesNullUse() throws Exception {
    String json =
        """
        {"Go": "1.22"}
        """;
    GoWorkspace workspace = MAPPER.readValue(json, GoWorkspace.class);
    assertThat(workspace.use()).isNull();
  }

  @Test
  void goWorkspace_handlesEmptyUse() throws Exception {
    String json =
        """
        {"Go": "1.22", "Use": []}
        """;
    GoWorkspace workspace = MAPPER.readValue(json, GoWorkspace.class);
    assertThat(workspace.use()).isEmpty();
  }

  @Test
  void goWorkspace_ignoresUnknownFields() throws Exception {
    String json =
        """
        {
            "Go": "1.22",
            "Use": [{"DiskPath": "./mod"}],
            "Replace": null,
            "Toolchain": {"Name": "go1.22.0"}
        }
        """;
    GoWorkspace workspace = MAPPER.readValue(json, GoWorkspace.class);
    assertThat(workspace.use()).hasSize(1);
  }

  // --- discoverWorkspaceManifests tests (require mocking Operations) ---

  @Test
  void discoverWorkspaceManifests_goMultiModule() throws IOException {
    Path workspaceDir = GO_FIXTURES.resolve("go_workspace").toAbsolutePath().normalize();
    String goWorkJson = buildGoWorkJson("./module-a", "./module-b");

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockGoOperations(mockOps, workspaceDir, goWorkJson);

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(2);
      assertThat(manifests).allMatch(p -> p.toString().endsWith("go.mod"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().contains("module-a" + File.separator + "go.mod"));
      assertThat(manifests)
          .anyMatch(p -> p.toString().contains("module-b" + File.separator + "go.mod"));
    }
  }

  @Test
  void discoverWorkspaceManifests_nestedModules() throws IOException {
    Path workspaceDir = GO_FIXTURES.resolve("go_workspace_nested").toAbsolutePath().normalize();
    String goWorkJson = buildGoWorkJson("./libs/core", "./libs/util");

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockGoOperations(mockOps, workspaceDir, goWorkJson);

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(2);
      assertThat(manifests)
          .anyMatch(
              p ->
                  p.toString()
                      .contains("libs" + File.separator + "core" + File.separator + "go.mod"));
      assertThat(manifests)
          .anyMatch(
              p ->
                  p.toString()
                      .contains("libs" + File.separator + "util" + File.separator + "go.mod"));
    }
  }

  @Test
  void discoverWorkspaceManifests_singleModule() throws IOException {
    Path workspaceDir = GO_FIXTURES.resolve("go_workspace_single").toAbsolutePath().normalize();
    String goWorkJson = buildGoWorkJson("./mymod");

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockGoOperations(mockOps, workspaceDir, goWorkJson);

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst().toString()).contains("mymod" + File.separator + "go.mod");
    }
  }

  @Test
  void discoverWorkspaceManifests_missingModuleDirectory() throws IOException {
    Path workspaceDir =
        GO_FIXTURES.resolve("go_workspace_missing_module").toAbsolutePath().normalize();
    String goWorkJson = buildGoWorkJson("./existing", "./nonexistent");

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockGoOperations(mockOps, workspaceDir, goWorkJson);

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).hasSize(1);
      assertThat(manifests.getFirst().toString()).contains("existing");
      assertThat(manifests).noneMatch(p -> p.toString().contains("nonexistent"));
    }
  }

  @Test
  void discoverWorkspaceManifests_goCommandFails() throws IOException {
    Path workspaceDir = GO_FIXTURES.resolve("go_workspace").toAbsolutePath().normalize();

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockOps.when(() -> Operations.getCustomPathOrElse("go")).thenReturn("go");
      mockOps
          .when(
              () ->
                  Operations.runProcessGetFullOutput(
                      eq(workspaceDir), any(String[].class), isNull()))
          .thenReturn(new Operations.ProcessExecOutput("", "go: not found", 1));

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).isEmpty();
    }
  }

  @Test
  void discoverWorkspaceManifests_emptyUseList() throws IOException {
    Path workspaceDir = GO_FIXTURES.resolve("go_workspace").toAbsolutePath().normalize();
    String goWorkJson =
        """
        {"Go": "1.22", "Use": []}
        """;

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockGoOperations(mockOps, workspaceDir, goWorkJson);

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

      assertThat(manifests).isEmpty();
    }
  }

  @Test
  void discoverWorkspaceManifests_ignorePatternFiltering() throws IOException {
    Path workspaceDir = GO_FIXTURES.resolve("go_workspace_nested").toAbsolutePath().normalize();
    String goWorkJson = buildGoWorkJson("./libs/core", "./libs/util");

    try (MockedStatic<Operations> mockOps = Mockito.mockStatic(Operations.class)) {
      mockGoOperations(mockOps, workspaceDir, goWorkJson);

      ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
      List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of("**/util/**"));

      assertThat(manifests).anyMatch(p -> p.toString().contains("core"));
      assertThat(manifests).noneMatch(p -> p.toString().contains("util"));
    }
  }

  // --- helpers ---

  private static String buildGoWorkJson(String... diskPaths) {
    StringBuilder sb = new StringBuilder("{\"Go\": \"1.22\", \"Use\": [");
    for (int i = 0; i < diskPaths.length; i++) {
      if (i > 0) sb.append(", ");
      sb.append("{\"DiskPath\": \"").append(diskPaths[i]).append("\"}");
    }
    sb.append("]}");
    return sb.toString();
  }

  private static void mockGoOperations(
      MockedStatic<Operations> mockOps, Path workspaceDir, String goWorkJson) {
    mockOps.when(() -> Operations.getCustomPathOrElse("go")).thenReturn("go");
    mockOps
        .when(
            () ->
                Operations.runProcessGetFullOutput(eq(workspaceDir), any(String[].class), isNull()))
        .thenReturn(new Operations.ProcessExecOutput(goWorkJson, "", 0));
  }
}
