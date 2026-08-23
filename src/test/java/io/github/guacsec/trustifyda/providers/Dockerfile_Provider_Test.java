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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.image.ImageUtils;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/** Tests for the DockerfileProvider batch multi-FROM behavior and Ecosystem integration. */
class Dockerfile_Provider_Test {

  private static final Path TEST_MANIFESTS = Path.of("src/test/resources/tst_manifests/dockerfile");
  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Nested
  class EcosystemIntegration {

    /**
     * Verifies that Ecosystem.getProvider returns a DockerfileProvider for Dockerfile manifests.
     */
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

    /** Verifies that non-Dockerfile files with a Dockerfile-like prefix are not matched. */
    @Test
    void resolve_provider_throws_for_non_dockerfile_prefix() {
      var manifestPath = Path.of("Dockerfilesomething");

      assertThatExceptionOfType(IllegalStateException.class)
          .isThrownBy(() -> Ecosystem.getProvider(manifestPath));
    }

    /** Verifies that both Dockerfile and Containerfile filenames resolve to DockerfileProvider. */
    @ParameterizedTest
    @MethodSource(
        "io.github.guacsec.trustifyda.providers.Dockerfile_Provider_Test#dockerfileManifests")
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
  }

  @Nested
  class ParseAllFromImages {

    /** Verifies that a single-stage Dockerfile returns a single-element list. */
    @Test
    void returns_single_element_list_for_single_from_dockerfile() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("single_stage/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images)
          .hasSize(1)
          .containsExactly("registry.access.redhat.com/ubi9/ubi-minimal:9.4");
    }

    /** Verifies that a multi-stage Dockerfile returns all FROM image references. */
    @Test
    void returns_all_images_from_multi_stage_dockerfile() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(2).containsExactly("node:18", "nginx:alpine");
    }

    /** Verifies that FROM with --platform flag extracts only the image reference. */
    @Test
    void strips_platform_flag() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("with_platform/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that FROM with multiple flags extracts only the image reference. */
    @Test
    void strips_multiple_flags() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("multiple_flags/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that image references with digests are parsed correctly. */
    @Test
    void handles_image_with_digest() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("with_digest/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("httpd@sha256:abc123");
    }

    /** Verifies that FROM line parsing is case-insensitive. */
    @Test
    void handles_lowercase_from_keyword() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("lowercase_from/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("alpine:3.18");
    }

    /** Verifies that ARG with default value is resolved in FROM line using ${VAR} syntax. */
    @Test
    void resolves_arg_substitution_with_braced_syntax() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("arg_substitution/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that ARG with default value is resolved in FROM line using $VAR syntax. */
    @Test
    void resolves_arg_substitution_with_bare_syntax() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("arg_bare_var/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that double-quoted ARG default values are unquoted before resolution. */
    @Test
    void resolves_arg_with_double_quoted_value() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("arg_double_quoted/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that single-quoted ARG default values are unquoted before resolution. */
    @Test
    void resolves_arg_with_single_quoted_value() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("arg_single_quoted/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that ARG values with spaces are captured fully when quoted. */
    @Test
    void resolves_arg_with_spaces_in_quoted_value() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("arg_value_with_spaces/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("ubuntu:22.04");
    }

    /** Verifies that ARG without default value causes the FROM line to be skipped. */
    @Test
    void skips_arg_substitution_without_default_value() {
      var dockerfile = TEST_MANIFESTS.resolve("arg_no_default/Dockerfile");

      assertThatExceptionOfType(IOException.class)
          .isThrownBy(() -> DockerfileProvider.parseAllFromImages(dockerfile))
          .withMessageContaining("No analyzable FROM instruction found");
    }

    /** Verifies that multi-stage mixed Dockerfile resolves ARGs and skips scratch. */
    @Test
    void resolves_args_and_skips_scratch_in_mixed_dockerfile() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("multi_stage_mixed/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(3).containsExactly("ubuntu:22.04", "node:18", "nginx:alpine");
    }

    /** Verifies that FROM scratch lines are skipped and remaining images are returned. */
    @Test
    void skips_scratch_and_returns_remaining_images() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("multi_stage_mixed/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).doesNotContain("scratch");
    }

    /** Verifies that FROM SCRATCH (uppercase) is skipped case-insensitively. */
    @Test
    void skips_scratch_case_insensitively() throws IOException {
      var dockerfile = TEST_MANIFESTS.resolve("scratch_uppercase/Dockerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(dockerfile);

      assertThat(images).hasSize(1).containsExactly("node:18");
      assertThat(images).doesNotContain("SCRATCH");
    }

    /** Verifies that a Dockerfile with no analyzable FROM instructions throws IOException. */
    @Test
    void throws_when_no_analyzable_from_instruction() {
      var dockerfile = TEST_MANIFESTS.resolve("no_from/Dockerfile");

      assertThatExceptionOfType(IOException.class)
          .isThrownBy(() -> DockerfileProvider.parseAllFromImages(dockerfile))
          .withMessageContaining("No analyzable FROM instruction found");
    }

    /** Verifies that a Dockerfile where all FROM lines are invalid throws IOException. */
    @Test
    void throws_when_all_from_lines_are_invalid() {
      var dockerfile = TEST_MANIFESTS.resolve("all_invalid/Dockerfile");

      assertThatExceptionOfType(IOException.class)
          .isThrownBy(() -> DockerfileProvider.parseAllFromImages(dockerfile))
          .withMessageContaining("No analyzable FROM instruction found");
    }

    /** Verifies that a Containerfile returns the correct image reference. */
    @Test
    void parses_containerfile() throws IOException {
      var containerfile = TEST_MANIFESTS.resolve("containerfile/Containerfile");

      List<String> images = DockerfileProvider.parseAllFromImages(containerfile);

      assertThat(images).hasSize(1).containsExactly("registry.access.redhat.com/ubi9/ubi:9.4");
    }
  }

  @Nested
  class ParseImageRefs {

    /** Verifies that a single-stage Dockerfile returns one ImageRef. */
    @Test
    void returns_single_image_ref_for_single_from_dockerfile() throws Exception {
      var dockerfile = TEST_MANIFESTS.resolve("single_stage/Dockerfile");
      ImageRef imageRef = Mockito.mock(ImageRef.class);

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock
            .when(() -> ImageUtils.parseImageRef("registry.access.redhat.com/ubi9/ubi-minimal:9.4"))
            .thenReturn(imageRef);

        Set<ImageRef> result = DockerfileProvider.parseImageRefs(dockerfile);

        assertThat(result).hasSize(1).containsExactly(imageRef);
      }
    }

    /** Verifies that a multi-stage Dockerfile returns all ImageRefs in FROM order. */
    @Test
    void returns_all_image_refs_for_multi_stage_dockerfile() throws Exception {
      var dockerfile = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");
      ImageRef nodeRef = Mockito.mock(ImageRef.class);
      ImageRef nginxRef = Mockito.mock(ImageRef.class);

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("node:18")).thenReturn(nodeRef);
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("nginx:alpine")).thenReturn(nginxRef);

        Set<ImageRef> result = DockerfileProvider.parseImageRefs(dockerfile);

        assertThat(result).hasSize(2).containsExactly(nodeRef, nginxRef);
      }
    }

    /** Verifies that failing images are skipped and remaining ImageRefs are returned. */
    @Test
    void skips_failing_images_and_returns_remaining() throws Exception {
      var dockerfile = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");
      ImageRef nginxRef = Mockito.mock(ImageRef.class);

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock
            .when(() -> ImageUtils.parseImageRef("node:18"))
            .thenThrow(new RuntimeException("skopeo not available"));
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("nginx:alpine")).thenReturn(nginxRef);

        Set<ImageRef> result = DockerfileProvider.parseImageRefs(dockerfile);

        assertThat(result).hasSize(1).containsExactly(nginxRef);
      }
    }

    /** Verifies that IOException is thrown when all images fail to parse. */
    @Test
    void throws_when_all_images_fail() {
      var dockerfile = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock
            .when(() -> ImageUtils.parseImageRef(Mockito.anyString()))
            .thenThrow(new RuntimeException("skopeo not available"));

        assertThatExceptionOfType(IOException.class)
            .isThrownBy(() -> DockerfileProvider.parseImageRefs(dockerfile))
            .withMessageContaining("No analyzable FROM images found");
      }
    }
  }

  @Nested
  class BatchContent {

    /** Verifies that provideStack returns batch content with SBOMs for all FROM images. */
    @Test
    void provide_stack_returns_batch_content_for_multi_stage_dockerfile() throws Exception {
      // Given a multi-stage Dockerfile with two valid FROM images
      var manifestPath = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");
      var provider = new DockerfileProvider(manifestPath);

      JsonNode nodeSbom = MAPPER.createObjectNode().put("bomFormat", "CycloneDX");
      ImageRef nodeRef = Mockito.mock(ImageRef.class);
      PackageURL nodePurl = new PackageURL("pkg:oci/node@18");
      Mockito.when(nodeRef.getPackageURL()).thenReturn(nodePurl);

      JsonNode nginxSbom = MAPPER.createObjectNode().put("bomFormat", "CycloneDX");
      ImageRef nginxRef = Mockito.mock(ImageRef.class);
      PackageURL nginxPurl = new PackageURL("pkg:oci/nginx@alpine");
      Mockito.when(nginxRef.getPackageURL()).thenReturn(nginxPurl);

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("node:18")).thenReturn(nodeRef);
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("nginx:alpine")).thenReturn(nginxRef);
        imageUtilsMock.when(() -> ImageUtils.generateImageSBOM(nodeRef)).thenReturn(nodeSbom);
        imageUtilsMock.when(() -> ImageUtils.generateImageSBOM(nginxRef)).thenReturn(nginxSbom);

        // When
        Provider.Content content = provider.provideStack();

        // Then
        assertThat(content.batch).isTrue();
        assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);

        JsonNode batchJson = MAPPER.readTree(content.buffer);
        assertThat(batchJson.isObject()).isTrue();
        assertThat(batchJson.size()).isEqualTo(2);
        assertThat(batchJson.has(nodePurl.toString())).isTrue();
        assertThat(batchJson.has(nginxPurl.toString())).isTrue();
      }
    }

    /** Verifies that provideComponent returns batch content with correct purl keys. */
    @Test
    void provide_component_returns_batch_content_with_correct_purl_keys() throws Exception {
      // Given a single-stage Dockerfile
      var manifestPath = TEST_MANIFESTS.resolve("single_stage/Dockerfile");
      var provider = new DockerfileProvider(manifestPath);

      JsonNode sbom = MAPPER.createObjectNode().put("bomFormat", "CycloneDX");
      ImageRef imageRef = Mockito.mock(ImageRef.class);
      PackageURL purl =
          new PackageURL("pkg:oci/ubi-minimal@9.4?repository_url=registry.access.redhat.com");
      Mockito.when(imageRef.getPackageURL()).thenReturn(purl);

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock
            .when(() -> ImageUtils.parseImageRef("registry.access.redhat.com/ubi9/ubi-minimal:9.4"))
            .thenReturn(imageRef);
        imageUtilsMock.when(() -> ImageUtils.generateImageSBOM(imageRef)).thenReturn(sbom);

        // When
        Provider.Content content = provider.provideComponent();

        // Then batch with one entry for single-FROM Dockerfile
        assertThat(content.batch).isTrue();
        assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);

        JsonNode batchJson = MAPPER.readTree(content.buffer);
        assertThat(batchJson.isObject()).isTrue();
        assertThat(batchJson.size()).isEqualTo(1);
        assertThat(batchJson.has(purl.toString())).isTrue();
        assertThat(batchJson.get(purl.toString()).get("bomFormat").asText()).isEqualTo("CycloneDX");
      }
    }

    /** Verifies that batch content skips images that fail SBOM generation and includes the rest. */
    @Test
    void provide_stack_skips_failing_images_in_batch() throws Exception {
      // Given a multi-stage Dockerfile where one image fails SBOM generation
      var manifestPath = TEST_MANIFESTS.resolve("multi_stage/Dockerfile");
      var provider = new DockerfileProvider(manifestPath);

      ImageRef nodeRef = Mockito.mock(ImageRef.class);
      JsonNode nginxSbom = MAPPER.createObjectNode().put("bomFormat", "CycloneDX");
      ImageRef nginxRef = Mockito.mock(ImageRef.class);
      PackageURL nginxPurl = new PackageURL("pkg:oci/nginx@alpine");
      Mockito.when(nginxRef.getPackageURL()).thenReturn(nginxPurl);

      try (MockedStatic<ImageUtils> imageUtilsMock = Mockito.mockStatic(ImageUtils.class)) {
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("node:18")).thenReturn(nodeRef);
        imageUtilsMock
            .when(() -> ImageUtils.generateImageSBOM(nodeRef))
            .thenThrow(new IOException("syft not available"));
        imageUtilsMock.when(() -> ImageUtils.parseImageRef("nginx:alpine")).thenReturn(nginxRef);
        imageUtilsMock.when(() -> ImageUtils.generateImageSBOM(nginxRef)).thenReturn(nginxSbom);

        // When
        Provider.Content content = provider.provideStack();

        // Then only the successful image is included
        assertThat(content.batch).isTrue();
        JsonNode batchJson = MAPPER.readTree(content.buffer);
        assertThat(batchJson.size()).isEqualTo(1);
        assertThat(batchJson.has(nginxPurl.toString())).isTrue();
      }
    }
  }

  @Nested
  class ProviderProperties {

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

      provider.validateLockFile(TEST_MANIFESTS.resolve("single_stage"));
    }
  }

  static Stream<Arguments> dockerfileManifests() {
    return Stream.of(
        Arguments.of("Dockerfile", TEST_MANIFESTS.resolve("single_stage/Dockerfile")),
        Arguments.of("Containerfile", TEST_MANIFESTS.resolve("containerfile/Containerfile")));
  }
}
