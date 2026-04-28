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

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class UvWorkspaceDiscoveryTest {

  private static final Path UV_FIXTURES = Path.of("src/test/resources/tst_manifests/workspace/uv");

  @Test
  void discoverWorkspaceManifests_uvRootPackageWorkspace() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).hasSize(3);
    assertThat(manifests).allMatch(p -> p.toString().endsWith("pyproject.toml"));
    assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pyproject.toml"));
    assertThat(manifests)
        .anyMatch(
            p ->
                p.toString()
                    .contains(
                        "packages"
                            + File.separator
                            + "mid-pkg"
                            + File.separator
                            + "pyproject.toml"));
    assertThat(manifests)
        .anyMatch(
            p ->
                p.toString()
                    .contains(
                        "packages"
                            + File.separator
                            + "sub-pkg"
                            + File.separator
                            + "pyproject.toml"));
  }

  @Test
  void discoverWorkspaceManifests_uvVirtualWorkspace() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace_virtual").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).hasSize(2);
    assertThat(manifests).allMatch(p -> p.toString().endsWith("pyproject.toml"));
    assertThat(manifests).noneMatch(p -> p.equals(workspaceDir.resolve("pyproject.toml")));
    assertThat(manifests).anyMatch(p -> p.toString().contains("pkg-a"));
    assertThat(manifests).anyMatch(p -> p.toString().contains("pkg-b"));
  }

  @Test
  void discoverWorkspaceManifests_uvExcludePatterns() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace_exclude").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).anyMatch(p -> p.toString().contains("core"));
    assertThat(manifests).noneMatch(p -> p.toString().contains("internal"));
  }

  @Test
  void discoverWorkspaceManifests_uvNestedMultiplePatterns() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace_nested").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests)
        .anyMatch(
            p ->
                p.toString()
                    .contains(
                        "apps" + File.separator + "backend" + File.separator + "pyproject.toml"));
    assertThat(manifests)
        .anyMatch(
            p ->
                p.toString()
                    .contains(
                        "libs" + File.separator + "core" + File.separator + "pyproject.toml"));
  }

  @Test
  void discoverWorkspaceManifests_uvNoLockFile() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace_no_lock").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).isEmpty();
  }

  @Test
  void discoverWorkspaceManifests_uvNoWorkspaceConfig() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace_no_config").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).isEmpty();
  }

  @Test
  void discoverWorkspaceManifests_uvIgnorePatternFiltering() throws IOException {
    Path workspaceDir = UV_FIXTURES.resolve("uv_workspace_nested").toAbsolutePath().normalize();

    ExhortApi api = new ExhortApi(Mockito.mock(java.net.http.HttpClient.class));
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of("**/libs/**"));

    assertThat(manifests).anyMatch(p -> p.toString().contains("backend"));
    assertThat(manifests)
        .noneMatch(p -> p.toString().contains(File.separator + "libs" + File.separator));
  }
}
