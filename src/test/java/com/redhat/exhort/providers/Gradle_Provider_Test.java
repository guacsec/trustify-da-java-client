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
package com.redhat.exhort.providers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mockStatic;

import com.redhat.exhort.Api;
import com.redhat.exhort.ExhortTest;
import com.redhat.exhort.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedStatic;

abstract class Gradle_Provider_Test extends ExhortTest {

  abstract String getProviderFolder();

  abstract String getManifestName();

  abstract String getSettingsName();

  //  private static System.Logger log = System.getLogger("Gradle_Provider_Test");
  // test folder are located at src/test/resources/tst_manifests
  // each folder should contain:
  // - build.gradle: the target manifest for testing
  // - expected_sbom.json: the SBOM expected to be provided
  static Stream<String> testFolders() {
    return Stream.of(
        "deps_with_ignore_full_specification",
        "deps_with_ignore_named_params",
        "deps_with_ignore_notations",
        "deps_with_no_ignore_common_paths",
        "deps_with_duplicate_no_version",
        "deps_with_duplicate_different_versions");
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideStack(String testFolder) throws IOException {
    // create temp file hosting our sut build.gradle
    var tmpGradleDir = Files.createTempDirectory("exhort_test_");
    var tmpGradleFile = Files.createFile(tmpGradleDir.resolve(getManifestName()));
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, getManifestName()))) {
      Files.write(tmpGradleFile, is.readAllBytes());
    }
    var settingsFile = Files.createFile(tmpGradleDir.resolve(getSettingsName()));
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, getSettingsName()))) {
      Files.write(settingsFile, is.readAllBytes());
    }
    var subGradleDir = Files.createDirectories(tmpGradleDir.resolve("gradle"));
    var libsVersionFile = Files.createFile(subGradleDir.resolve("libs.versions.toml"));
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/",
                    "tst_manifests",
                    getProviderFolder(),
                    testFolder,
                    "gradle",
                    "libs.versions.toml"))) {
      Files.write(libsVersionFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/",
                    "tst_manifests",
                    getProviderFolder(),
                    testFolder,
                    "expected_stack_sbom.json"))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String depTree;
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, "depTree.txt"))) {
      depTree = new String(is.readAllBytes());
    }
    String gradleProperties;
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, "gradle.properties"))) {
      gradleProperties = new String(is.readAllBytes());
    }

    ArgumentMatcher<String> gradle = string -> string.equals("gradle");
    ArgumentMatcher<String> dependencies = string -> string.equals("dependencies");
    ArgumentMatcher<String> properties = string -> string.equals("properties");
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");
      mockedOperations
          .when(() -> Operations.getExecutable("gradle", "--version"))
          .thenReturn("gradle");
      mockedOperations
          .when(
              () ->
                  Operations.runProcessGetOutput(
                      any(Path.class), argThat(gradle), argThat(dependencies)))
          .thenReturn(depTree);
      mockedOperations
          .when(
              () ->
                  Operations.runProcessGetOutput(
                      any(Path.class), argThat(gradle), argThat(properties)))
          .thenReturn(gradleProperties);

      // when providing stack content for our pom
      var content = new GradleProvider(tmpGradleFile).provideStack();
      // cleanup
      Files.deleteIfExists(tmpGradleFile);

      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent(String testFolder) throws IOException {
    // create temp file hosting our sut build.gradle
    var tmpGradleDir = Files.createTempDirectory("exhort_test_");
    var tmpGradleFile = Files.createFile(tmpGradleDir.resolve(getManifestName()));
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, getManifestName()))) {
      Files.write(tmpGradleFile, is.readAllBytes());
    }
    var settingsFile = Files.createFile(tmpGradleDir.resolve(getSettingsName()));
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, getSettingsName()))) {
      Files.write(settingsFile, is.readAllBytes());
    }
    var subGradleDir = Files.createDirectories(tmpGradleDir.resolve("gradle"));
    var libsVersionFile = Files.createFile(subGradleDir.resolve("libs.versions.toml"));
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/",
                    "tst_manifests",
                    getProviderFolder(),
                    testFolder,
                    "gradle",
                    "libs.versions.toml"))) {
      Files.write(libsVersionFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/",
                    "tst_manifests",
                    getProviderFolder(),
                    testFolder,
                    "expected_component_sbom.json"))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String depTree;
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, "depTree.txt"))) {
      depTree = new String(is.readAllBytes());
    }
    String gradleProperties;
    try (var is =
        getClass()
            .getClassLoader()
            .getResourceAsStream(
                String.join(
                    "/", "tst_manifests", getProviderFolder(), testFolder, "gradle.properties"))) {
      gradleProperties = new String(is.readAllBytes());
    }

    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      ArgumentMatcher<String> gradle = string -> string.equals("gradle");
      ArgumentMatcher<String> dependencies = string -> string.equals("dependencies");
      ArgumentMatcher<String> properties = string -> string.equals("properties");
      mockedOperations.when(() -> Operations.getCustomPathOrElse("gradle")).thenReturn("gradle");
      mockedOperations
          .when(() -> Operations.getExecutable("gradle", "--version"))
          .thenReturn("gradle");
      mockedOperations
          .when(
              () ->
                  Operations.runProcessGetOutput(
                      any(Path.class), argThat(gradle), argThat(dependencies)))
          .thenReturn(depTree);
      mockedOperations
          .when(
              () ->
                  Operations.runProcessGetOutput(
                      any(Path.class), argThat(gradle), argThat(properties)))
          .thenReturn(gradleProperties);

      // when providing component content for our pom
      var content = new GradleProvider(tmpGradleFile).provideComponent();
      // cleanup
      Files.deleteIfExists(tmpGradleFile);
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  private String dropIgnored(String s) {
    return s.replaceAll("\\s+", "").replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\",", "");
  }
}
