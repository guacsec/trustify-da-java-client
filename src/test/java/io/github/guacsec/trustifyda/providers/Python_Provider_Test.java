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

import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PIP_FREEZE;
import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PIP_PIPDEPTREE;
import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PIP_SHOW;
import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PIP_USE_DEP_TREE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.utils.PythonControllerBase;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.junitpioneer.jupiter.SetSystemProperty;

@ExtendWith(PythonEnvironmentExtension.class)
class Python_Provider_Test extends ExhortTest {

  static Stream<String> testFolders() {
    return Stream.of("pip_requirements_txt_no_ignore", "pip_requirements_txt_ignore");
  }

  public Python_Provider_Test(PythonControllerBase pythonController) {
    this.pythonController = pythonController;
  }

  private final PythonControllerBase pythonController;

  @EnabledIfEnvironmentVariable(named = "RUN_PYTHON_BIN", matches = "true")
  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideStack(String testFolder) throws IOException {
    // create temp file hosting our sut package.json
    var tmpPythonModuleDir = Files.createTempDirectory("trustify_da_test_");
    var tmpPythonFile = Files.createFile(tmpPythonModuleDir.resolve("requirements.txt"));
    var provider = new PythonPipProvider(tmpPythonFile);
    provider.setPythonController(pythonController);
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/pip/%s/requirements.txt", testFolder))) {
      Files.write(tmpPythonFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/pip/%s/expected_stack_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    // when providing stack content for our pom
    var content = provider.provideStack();
    // cleanup
    Files.deleteIfExists(tmpPythonFile);
    Files.deleteIfExists(tmpPythonModuleDir);
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @EnabledIfEnvironmentVariable(named = "RUN_PYTHON_BIN", matches = "true")
  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent(String testFolder) throws IOException {
    // load the pom target pom file
    var requirementsFile =
        Path.of(
            String.format("src/test/resources/tst_manifests/pip/%s/requirements.txt", testFolder));

    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/pip/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    // when providing component content for our pom
    var content = new PythonPipProvider(requirementsFile).provideComponent();
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  @SetSystemProperty(key = PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV, value = "true")
  @RestoreSystemProperties
  void test_the_provideStack_with_properties(String testFolder) throws IOException {
    // create temp file hosting our sut package.json
    var tmpPythonModuleDir = Files.createTempDirectory("trustify_da_test_");
    var tmpPythonFile = Files.createFile(tmpPythonModuleDir.resolve("requirements.txt"));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/pip/%s/requirements.txt", testFolder))) {
      Files.write(tmpPythonFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/pip/%s/expected_stack_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    // when providing stack content for our pom
    var content = new PythonPipProvider(tmpPythonFile).provideStack();
    String pipShowContent = this.getStringFromFile("tst_manifests/pip/pip-show.txt");
    String pipFreezeContent = this.getStringFromFile("tst_manifests/pip/pip-freeze-all.txt");
    String base64PipShow = new String(Base64.getEncoder().encode(pipShowContent.getBytes()));
    String base64PipFreeze = new String(Base64.getEncoder().encode(pipFreezeContent.getBytes()));
    System.setProperty(PROP_TRUSTIFY_DA_PIP_SHOW, base64PipShow);
    System.setProperty(PROP_TRUSTIFY_DA_PIP_FREEZE, base64PipFreeze);
    // cleanup
    Files.deleteIfExists(tmpPythonFile);
    Files.deleteIfExists(tmpPythonModuleDir);
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  @SetSystemProperty(key = PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV, value = "true")
  @SetSystemProperty(key = PROP_TRUSTIFY_DA_PIP_USE_DEP_TREE, value = "true")
  @RestoreSystemProperties
  void test_the_provideStack_with_pipdeptree(String testFolder) throws IOException {
    // create temp file hosting our sut package.json
    var tmpPythonModuleDir = Files.createTempDirectory("trustify_da_test_");
    var tmpPythonFile = Files.createFile(tmpPythonModuleDir.resolve("requirements.txt"));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/pip/%s/requirements.txt", testFolder))) {
      Files.write(tmpPythonFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/pip/%s/expected_stack_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    // when providing stack content for our pom
    var content = new PythonPipProvider(tmpPythonFile).provideStack();
    String pipdeptreeContent = this.getStringFromFile("tst_manifests/pip/pipdeptree.json");
    String base64Pipdeptree = new String(Base64.getEncoder().encode(pipdeptreeContent.getBytes()));
    System.setProperty(PROP_TRUSTIFY_DA_PIP_PIPDEPTREE, base64Pipdeptree);
    // cleanup
    Files.deleteIfExists(tmpPythonFile);
    Files.deleteIfExists(tmpPythonModuleDir);
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  @RestoreSystemProperties
  void test_the_provideComponent_with_properties(String testFolder) throws IOException {
    // load the pom target pom file
    var targetRequirements =
        String.format("src/test/resources/tst_manifests/pip/%s/requirements.txt", testFolder);

    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/pip/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String pipShowContent = this.getStringFromFile("tst_manifests/pip/pip-show.txt");
    String pipFreezeContent = this.getStringFromFile("tst_manifests/pip/pip-freeze-all.txt");
    String base64PipShow = new String(Base64.getEncoder().encode(pipShowContent.getBytes()));
    String base64PipFreeze = new String(Base64.getEncoder().encode(pipFreezeContent.getBytes()));
    System.setProperty(PROP_TRUSTIFY_DA_PIP_SHOW, base64PipShow);
    System.setProperty(PROP_TRUSTIFY_DA_PIP_FREEZE, base64PipFreeze);
    // when providing component content for our pom
    var content = new PythonPipProvider(Path.of(targetRequirements)).provideComponent();
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @Test
  void Test_The_ProvideComponent_Path_Should_Throw_Exception() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new PythonPipProvider(Path.of(".")).provideComponent());
  }

  private String dropIgnored(String s) {
    return s.replaceAll("\\s+", "").replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"", "");
  }
}
