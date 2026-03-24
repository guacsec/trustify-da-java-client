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
import static org.assertj.core.api.Assertions.assertThatNoException;

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.utils.PythonControllerTestEnv;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class Python_Pyproject_Provider_Test extends ExhortTest {

  @Test
  void test_ecosystem_resolves_pyproject_toml() {
    var provider =
        Ecosystem.getProvider(
            Path.of(
                "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml"));
    assertThat(provider).isInstanceOf(PythonPyprojectProvider.class);
    assertThat(provider.ecosystem).isEqualTo(Ecosystem.Type.PYTHON);
  }

  @Test
  void test_parse_pep621_dependencies() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    List<String> deps = provider.parseDependencyStrings();
    assertThat(deps).contains("anyio==3.6.2", "flask==2.0.3", "requests==2.25.1");
  }

  @Test
  void test_parse_pep621_excludes_optional_dependencies() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    List<String> deps = provider.parseDependencyStrings();
    assertThat(deps).doesNotContain("click==8.0.4");
  }

  @Test
  void test_parse_poetry_dependencies_converts_to_pep440() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_poetry/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    List<String> deps = provider.parseDependencyStrings();
    assertThat(deps)
        .contains("anyio>=3.6.2,<4.0.0", "flask>=2.0.3,<3.0.0", "requests>=2.25.1,<3.0.0");
  }

  @Test
  void test_parse_poetry_excludes_python() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_poetry/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    List<String> deps = provider.parseDependencyStrings();
    assertThat(deps).doesNotContain("python");
  }

  @Test
  void test_parse_poetry_excludes_dev_group_dependencies() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_poetry/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    List<String> deps = provider.parseDependencyStrings();
    assertThat(deps).doesNotContain("click", "click>=8.0.4,<9.0.0");
  }

  @Test
  void test_convert_caret_major() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("^3.6.2")).isEqualTo(">=3.6.2,<4.0.0");
  }

  @Test
  void test_convert_caret_zero_major() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("^0.5.1")).isEqualTo(">=0.5.1,<0.6.0");
  }

  @Test
  void test_convert_caret_zero_zero() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("^0.0.3")).isEqualTo(">=0.0.3,<0.0.4");
  }

  @Test
  void test_convert_caret_two_parts() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("^2.0")).isEqualTo(">=2.0.0,<3.0.0");
  }

  @Test
  void test_convert_tilde() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("~1.2.3")).isEqualTo(">=1.2.3,<1.3.0");
  }

  @Test
  void test_convert_tilde_two_parts() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("~1.2")).isEqualTo(">=1.2.0,<1.3.0");
  }

  @Test
  void test_pep440_passthrough() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion(">=2.0")).isEqualTo(">=2.0");
    assertThat(PythonPyprojectProvider.convertPoetryVersion("==1.0.0")).isEqualTo("==1.0.0");
    assertThat(PythonPyprojectProvider.convertPoetryVersion("~=1.4")).isEqualTo("~=1.4");
  }

  @Test
  void test_convert_bare_version_prepends_equals() {
    assertThat(PythonPyprojectProvider.convertPoetryVersion("1.2.3")).isEqualTo("==1.2.3");
    assertThat(PythonPyprojectProvider.convertPoetryVersion("2.0")).isEqualTo("==2.0");
  }

  @Test
  void test_convert_caret_prerelease_does_not_crash() {
    assertThatNoException()
        .isThrownBy(() -> PythonPyprojectProvider.convertPoetryVersion("^1.2.3b1"));
    assertThat(PythonPyprojectProvider.convertPoetryVersion("^1.2.3b1"))
        .isEqualTo(">=1.2.3,<2.0.0");
  }

  @Test
  void test_convert_tilde_prerelease_does_not_crash() {
    assertThatNoException()
        .isThrownBy(() -> PythonPyprojectProvider.convertPoetryVersion("~1.2.3rc1"));
    assertThat(PythonPyprojectProvider.convertPoetryVersion("~1.2.3rc1"))
        .isEqualTo(">=1.2.3,<1.3.0");
  }

  @Test
  void test_ignored_deps_collected_during_parsing() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_ignore/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    provider.parseDependencyStrings();
    String manifestContent = Files.readString(pyprojectPath);
    var ignored = provider.getIgnoredDependencies(manifestContent);
    Set<String> ignoredNames =
        ignored.stream().map(purl -> purl.getName()).collect(Collectors.toSet());
    assertThat(ignoredNames).contains("flask");
    assertThat(ignoredNames).doesNotContain("anyio", "requests");
  }

  @Test
  void test_provideComponent_generates_correct_media_type() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    var tmpDir = Files.createTempDirectory("trustify_da_test_");
    var tmpFile = Files.createFile(tmpDir.resolve("pyproject.toml"));
    Files.copy(pyprojectPath, tmpFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    var provider = new PythonPyprojectProvider(tmpFile);
    var mockController =
        new PythonControllerTestEnv(
            io.github.guacsec.trustifyda.tools.Operations.getCustomPathOrElse("python3"),
            io.github.guacsec.trustifyda.tools.Operations.getCustomPathOrElse("pip3"));
    provider.setPythonController(mockController);
    try {
      var content = provider.provideComponent();
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      String sbomJson = new String(content.buffer);
      assertThat(sbomJson).contains("CycloneDX");
      assertThat(sbomJson).contains("pkg:pypi/");
    } catch (RuntimeException e) {
      Assumptions.assumeTrue(
          false, "Skipping: Python/pip environment not usable - " + e.getMessage());
    } finally {
      Files.deleteIfExists(tmpFile);
      Files.deleteIfExists(tmpDir);
    }
  }
}
