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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.guacsec.trustifyda.tools.Ecosystem;
import java.io.IOException;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Tests for the DockerfileProvider and its integration with Ecosystem. */
class Dockerfile_Provider_Test {

  private static final Path TEST_MANIFESTS = Path.of("src/test/resources/tst_manifests/dockerfile");

  /** Verifies that Ecosystem.getProvider returns a DockerfileProvider for Dockerfile manifests. */
  @Test
  void resolve_provider_returns_dockerfile_provider_for_dockerfile() {
    var manifestPath = TEST_MANIFESTS.resolve("single_stage/Dockerfile");
    var provider = Ecosystem.getProvider(manifestPath);

    assertThat(provider).isInstanceOf(DockerfileProvider.class);
  }

  /**
   * Verifies that Ecosystem.getProvider returns a DockerfileProvider for Containerfile manifests.
   */
  @Test
  void resolve_provider_returns_dockerfile_provider_for_containerfile() {
    var manifestPath = TEST_MANIFESTS.resolve("containerfile/Containerfile");
    var provider = Ecosystem.getProvider(manifestPath);

    assertThat(provider).isInstanceOf(DockerfileProvider.class);
  }

  /** Verifies that a single-stage Dockerfile extracts the correct image reference. */
  @Test
  void parse_from_extracts_image_from_single_stage_dockerfile() throws IOException {
    var dockerfile = TEST_MANIFESTS.resolve("single_stage/Dockerfile");

    String image = DockerfileProvider.parseLastFromImage(dockerfile);

    assertThat(image).isEqualTo("registry.access.redhat.com/ubi9/ubi-minimal:9.4");
  }

  /** Verifies that a multi-stage Dockerfile uses the last FROM instruction (final stage). */
  @Test
  void parse_from_uses_last_from_in_multi_stage_dockerfile() throws IOException {
    var dockerfile = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");

    String image = DockerfileProvider.parseLastFromImage(dockerfile);

    assertThat(image).isEqualTo("nginx:alpine");
  }

  /** Verifies that FROM with --platform flag extracts only the image reference. */
  @Test
  void parse_from_strips_platform_flag() throws IOException {
    var dockerfile = TEST_MANIFESTS.resolve("with_platform/Dockerfile");

    String image = DockerfileProvider.parseLastFromImage(dockerfile);

    assertThat(image).isEqualTo("ubuntu:22.04");
  }

  /** Verifies that a Dockerfile with no FROM instruction throws an IOException. */
  @Test
  void parse_from_throws_when_no_from_instruction() {
    var dockerfile = TEST_MANIFESTS.resolve("no_from/Dockerfile");

    assertThatExceptionOfType(IOException.class)
        .isThrownBy(() -> DockerfileProvider.parseLastFromImage(dockerfile))
        .withMessageContaining("No FROM instruction found");
  }

  /** Verifies that FROM with multiple flags extracts only the image reference. */
  @Test
  void parse_from_strips_multiple_flags() throws IOException {
    var dockerfile = TEST_MANIFESTS.resolve("multiple_flags/Dockerfile");

    String image = DockerfileProvider.parseLastFromImage(dockerfile);

    assertThat(image).isEqualTo("ubuntu:22.04");
  }

  /** Verifies that image references with digests are parsed correctly. */
  @Test
  void parse_from_handles_image_with_digest() throws IOException {
    var dockerfile = TEST_MANIFESTS.resolve("with_digest/Dockerfile");

    String image = DockerfileProvider.parseLastFromImage(dockerfile);

    assertThat(image).isEqualTo("httpd@sha256:abc123");
  }

  /** Verifies that ARG-substituted FROM targets are rejected with a clear error. */
  @Test
  void parse_from_throws_when_from_uses_arg_substitution() {
    var dockerfile = TEST_MANIFESTS.resolve("arg_substitution/Dockerfile");

    assertThatExceptionOfType(IOException.class)
        .isThrownBy(() -> DockerfileProvider.parseLastFromImage(dockerfile))
        .withMessageContaining("ARG substitution");
  }

  /** Verifies that FROM line parsing is case-insensitive. */
  @Test
  void parse_from_handles_lowercase_from_keyword() throws IOException {
    var dockerfile = TEST_MANIFESTS.resolve("lowercase_from/Dockerfile");

    String image = DockerfileProvider.parseLastFromImage(dockerfile);

    assertThat(image).isEqualTo("alpine:3.18");
  }

  /** Verifies that FROM scratch is rejected since there is no base image to analyze. */
  @Test
  void parse_from_throws_when_from_scratch() {
    var dockerfile = TEST_MANIFESTS.resolve("from_scratch/Dockerfile");

    assertThatExceptionOfType(IOException.class)
        .isThrownBy(() -> DockerfileProvider.parseLastFromImage(dockerfile))
        .withMessageContaining("FROM scratch");
  }

  /** Verifies that non-Dockerfile files with a Dockerfile-like prefix are not matched. */
  @Test
  void resolve_provider_throws_for_non_dockerfile_prefix() {
    // "Dockerfilesomething" without a dot separator should not be treated as a Dockerfile
    var manifestPath = Path.of("Dockerfilesomething");

    assertThatExceptionOfType(IllegalStateException.class)
        .isThrownBy(() -> Ecosystem.getProvider(manifestPath));
  }

  /** Verifies that readLicenseFromManifest returns null for Dockerfiles. */
  @Test
  void read_license_from_manifest_returns_null() {
    var provider = new DockerfileProvider(TEST_MANIFESTS.resolve("single_stage/Dockerfile"));

    assertThat(provider.readLicenseFromManifest()).isNull();
  }

  /** Verifies that validateLockFile returns without error (no lock file required). */
  @Test
  void validate_lock_file_does_not_throw() {
    var provider = new DockerfileProvider(TEST_MANIFESTS.resolve("single_stage/Dockerfile"));

    // Should not throw — Dockerfiles have no lock file requirement
    provider.validateLockFile(TEST_MANIFESTS.resolve("single_stage"));
  }

  /** Verifies that both Dockerfile and Containerfile filenames resolve to DockerfileProvider. */
  @ParameterizedTest
  @MethodSource("dockerfileManifests")
  void resolve_provider_returns_dockerfile_provider_for_all_supported_names(
      String description, Path manifestPath) {
    var provider = Ecosystem.getProvider(manifestPath);

    assertThat(provider).isInstanceOf(DockerfileProvider.class);
    assertThat(provider.ecosystem).isEqualTo(Ecosystem.Type.DOCKERFILE);
  }

  /** Verifies that suffixed Dockerfile names (e.g. Dockerfile.dev) are supported. */
  @Test
  void resolve_provider_returns_dockerfile_provider_for_suffixed_dockerfile() {
    var manifestPath = TEST_MANIFESTS.resolve("suffixed/Dockerfile.dev");
    var provider = Ecosystem.getProvider(manifestPath);

    assertThat(provider).isInstanceOf(DockerfileProvider.class);
    assertThat(provider.ecosystem).isEqualTo(Ecosystem.Type.DOCKERFILE);
  }

  static Stream<Arguments> dockerfileManifests() {
    return Stream.of(
        Arguments.of("Dockerfile", TEST_MANIFESTS.resolve("single_stage/Dockerfile")),
        Arguments.of("Containerfile", TEST_MANIFESTS.resolve("containerfile/Containerfile")));
  }
}
