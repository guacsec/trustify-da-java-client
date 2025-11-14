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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(HelperExtension.class)
@ExtendWith(MockitoExtension.class)
public class Java_Maven_Provider_Test extends ExhortTest {

  //  private static System.Logger log = System.getLogger("Java_Maven_Provider_Test");
  // test folder are located at src/test/resources/tst_manifests
  // each folder should contain:
  // - pom.xml: the target manifest for testing
  // - expected_sbom.json: the SBOM expected to be provided
  static Stream<String> testFolders() {
    return Stream.of(
        "pom_deps_with_no_ignore_provided_scope",
        "deps_no_trivial_with_ignore",
        "deps_with_ignore_on_artifact",
        "deps_with_ignore_on_dependency",
        "deps_with_ignore_on_group",
        "deps_with_ignore_on_version",
        "deps_with_ignore_on_wrong",
        "deps_with_no_ignore",
        "pom_deps_with_no_ignore_common_paths");
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideStack(String testFolder) throws IOException {
    // create temp file hosting our sut pom.xml
    var tmpPomFile = Files.createTempFile("TRUSTIFY_DA_test_", ".xml");
    try (var is =
        getResourceAsStreamDecision(
            getClass(), String.format("tst_manifests/maven/%s/pom.xml", testFolder))) {
      Files.write(tmpPomFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            getClass(),
            String.format("tst_manifests/maven/%s/expected_stack_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String depTree;
    try (var is =
        getResourceAsStreamDecision(
            getClass(), String.format("tst_manifests/maven/%s/depTree.txt", testFolder))) {
      depTree = new String(is.readAllBytes());
    }
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.runProcess(any(), any(), any()))
          .thenAnswer(
              invocationOnMock ->
                  getOutputFileAndOverwriteItWithMock(depTree, invocationOnMock, "-DoutputFile"));
      // Mock Operations.getCustomPathOrElse to return "mvn"
      mockedOperations.when(() -> Operations.getCustomPathOrElse(anyString())).thenReturn("mvn");
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString()))
          .thenReturn("mvn");

      // when providing stack content for our pom
      var content = new JavaMavenProvider(tmpPomFile).provideStack();
      // cleanup
      Files.deleteIfExists(tmpPomFile);
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  public static String getOutputFileAndOverwriteItWithMock(
      String outputFileContent, InvocationOnMock invocationOnMock, String parameterPrefix)
      throws IOException {
    String[] rawArguments = (String[]) invocationOnMock.getRawArguments()[1];
    Optional<String> outputFileArg =
        Arrays.stream(rawArguments)
            .filter(arg -> arg != null && arg.startsWith(parameterPrefix))
            .findFirst();
    String outputFilePath = null;
    if (outputFileArg.isPresent()) {
      String outputFile = outputFileArg.get();
      outputFilePath = outputFile.substring(outputFile.indexOf("=") + 1);
      Files.writeString(Path.of(outputFilePath), outputFileContent);
    }
    return outputFilePath;
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent(String testFolder) throws IOException {
    // load the pom target pom file
    var targetPom = resolveFile(String.format("tst_manifests/maven/%s/pom.xml", testFolder));

    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            getClass(),
            String.format("tst_manifests/maven/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }

    String effectivePom;
    try (var is =
        getResourceAsStreamDecision(
            getClass(), String.format("tst_manifests/maven/%s/effectivePom.xml", testFolder))) {
      effectivePom = new String(is.readAllBytes());
    }
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.runProcess(any(), any(), any()))
          .thenAnswer(
              invocationOnMock ->
                  getOutputFileAndOverwriteItWithMock(effectivePom, invocationOnMock, "-Doutput"));
      // Mock Operations.getCustomPathOrElse to return "mvn"
      mockedOperations.when(() -> Operations.getCustomPathOrElse(anyString())).thenReturn("mvn");
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString()))
          .thenReturn("mvn");

      // when providing component content for our pom
      var content = new JavaMavenProvider(targetPom).provideComponent();
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent_With_Path(String testFolder) throws IOException {
    // load the pom target pom file
    // create temp file hosting our sut pom.xml
    var tmpPomFile = Files.createTempFile("TRUSTIFY_DA_test_", ".xml");
    try (var is =
        getResourceAsStreamDecision(
            getClass(), String.format("tst_manifests/maven/%s/pom.xml", testFolder))) {
      Files.write(tmpPomFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            getClass(),
            String.format("tst_manifests/maven/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }

    String effectivePom;
    try (var is =
        getResourceAsStreamDecision(
            getClass(), String.format("tst_manifests/maven/%s/effectivePom.xml", testFolder))) {
      effectivePom = new String(is.readAllBytes());
    }
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.runProcess(any(), any(), any()))
          .thenAnswer(
              invocationOnMock ->
                  getOutputFileAndOverwriteItWithMock(effectivePom, invocationOnMock, "-Doutput"));
      // Mock Operations.getCustomPathOrElse to return "mvn"
      mockedOperations.when(() -> Operations.getCustomPathOrElse(anyString())).thenReturn("mvn");
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString()))
          .thenReturn("mvn");

      // when providing component content for our pom
      var content = new JavaMavenProvider(tmpPomFile).provideComponent();
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  private String dropIgnored(String s) {
    return s.replaceAll("\\s+", "").replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\",", "");
  }
}
