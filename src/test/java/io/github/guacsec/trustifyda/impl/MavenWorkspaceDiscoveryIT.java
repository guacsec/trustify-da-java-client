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

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("IntegrationTest")
class MavenWorkspaceDiscoveryIT {

  private static final Path MAVEN_FIXTURES =
      Path.of("src/test/resources/tst_manifests/workspace/maven");

  @BeforeAll
  static void requireMaven() {
    boolean mavenAvailable;
    try {
      Process p = new ProcessBuilder("mvn", "-v").redirectErrorStream(true).start();
      mavenAvailable = p.waitFor() == 0;
    } catch (Exception e) {
      mavenAvailable = false;
    }
    Assumptions.assumeTrue(mavenAvailable, "mvn not available on PATH");
  }

  @Test
  void discoverWorkspaceManifests_mavenMultiModule() throws IOException {
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();
    ExhortApi api = new ExhortApi();
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).hasSize(3);
    assertThat(manifests).allMatch(p -> p.getFileName().toString().equals("pom.xml"));
    assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
    assertThat(manifests).anyMatch(p -> p.toString().contains("module-a"));
    assertThat(manifests).anyMatch(p -> p.toString().contains("module-b"));
  }

  @Test
  void discoverWorkspaceManifests_nestedAggregator() throws IOException {
    Path workspaceDir =
        MAVEN_FIXTURES.resolve("maven_nested_aggregator").toAbsolutePath().normalize();
    ExhortApi api = new ExhortApi();
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

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

  @Test
  void discoverWorkspaceManifests_noModules() throws IOException {
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_no_modules").toAbsolutePath().normalize();
    ExhortApi api = new ExhortApi();
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).hasSize(1);
    assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
  }

  @Test
  void discoverWorkspaceManifests_missingModuleDirectory() throws IOException {
    // Maven fails to read the POM when a declared module directory is missing,
    // so graceful degradation returns only the root pom.xml.
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_missing_module").toAbsolutePath().normalize();
    ExhortApi api = new ExhortApi();
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of());

    assertThat(manifests).hasSize(1);
    assertThat(manifests.getFirst()).isEqualTo(workspaceDir.resolve("pom.xml"));
  }

  @Test
  void discoverWorkspaceManifests_ignorePatternFiltering() throws IOException {
    Path workspaceDir = MAVEN_FIXTURES.resolve("maven_multi_module").toAbsolutePath().normalize();
    ExhortApi api = new ExhortApi();
    List<Path> manifests = api.discoverWorkspaceManifests(workspaceDir, Set.of("**/module-b/**"));

    assertThat(manifests).anyMatch(p -> p.toString().contains("module-a"));
    assertThat(manifests).noneMatch(p -> p.toString().contains("module-b"));
  }
}
