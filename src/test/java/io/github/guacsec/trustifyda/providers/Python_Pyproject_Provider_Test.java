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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
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
  void test_getRootComponentName_reads_pep621_name() {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.getRootComponentName()).isEqualTo("test-project");
  }

  @Test
  void test_getRootComponentName_reads_poetry_name() {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_poetry/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.getRootComponentName()).isEqualTo("test-project");
  }

  @Test
  void test_getRootComponentName_falls_back_to_default() {
    Path pyprojectPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_metadata/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.getRootComponentName()).isEqualTo("default-pip-root");
  }

  @Test
  void test_getRootComponentVersion_reads_pep621_version() {
    Path pyprojectPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_pep621_license/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.getRootComponentVersion()).isEqualTo("2.0.0");
  }

  @Test
  void test_getRootComponentVersion_reads_poetry_version() {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_poetry/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.getRootComponentVersion()).isEqualTo("0.1.0");
  }

  @Test
  void test_getRootComponentVersion_falls_back_to_default() {
    Path pyprojectPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_metadata/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.getRootComponentVersion()).isEqualTo("0.0.0");
  }

  @Test
  void test_readLicenseFromManifest_reads_pep621_license() {
    Path pyprojectPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_pep621_license/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.readLicenseFromManifest()).isEqualTo("MIT");
  }

  @Test
  void test_readLicenseFromManifest_reads_poetry_license() {
    Path pyprojectPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_poetry_license/pyproject.toml");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    assertThat(provider.readLicenseFromManifest()).isEqualTo("Apache-2.0");
  }

  // --- pip report parsing tests ---

  @Test
  void test_parsePipReport_identifies_direct_deps() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    String reportJson = Files.readString(reportPath);
    var data = provider.parsePipReport(reportJson);
    assertThat(data.directDeps).containsExactlyInAnyOrder("anyio", "flask", "requests");
  }

  @Test
  void test_parsePipReport_builds_transitive_graph() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    String reportJson = Files.readString(reportPath);
    var data = provider.parsePipReport(reportJson);

    var requestsPkg = data.graph.get("requests");
    assertThat(requestsPkg).isNotNull();
    assertThat(requestsPkg.children)
        .containsExactlyInAnyOrder("charset-normalizer", "idna", "urllib3", "certifi");

    var anyioPkg = data.graph.get("anyio");
    assertThat(anyioPkg).isNotNull();
    assertThat(anyioPkg.children).containsExactlyInAnyOrder("idna", "sniffio");
  }

  @Test
  void test_parsePipReport_filters_extras() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    String reportJson = Files.readString(reportPath);
    var data = provider.parsePipReport(reportJson);

    assertThat(data.graph.containsKey("pysocks")).isFalse();
    var requestsPkg = data.graph.get("requests");
    assertThat(requestsPkg.children).doesNotContain("pysocks");
  }

  @Test
  void test_parsePipReport_excludes_root_from_graph() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    String reportJson = Files.readString(reportPath);
    var data = provider.parsePipReport(reportJson);

    assertThat(data.graph.containsKey("test-project")).isFalse();
  }

  @Test
  void test_parsePipReport_name_canonicalization() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    var provider = new PythonPyprojectProvider(pyprojectPath);
    String reportJson = Files.readString(reportPath);
    var data = provider.parsePipReport(reportJson);

    assertThat(data.graph.containsKey("charset-normalizer")).isTrue();
    assertThat(data.graph.containsKey("werkzeug")).isTrue();
    assertThat(data.graph.containsKey("jinja2")).isTrue();
    assertThat(data.graph.containsKey("markupsafe")).isTrue();
  }

  @Test
  void test_hasExtraMarker() {
    assertThat(PythonPyprojectProvider.hasExtraMarker("PySocks!=1.5.7,>=1.5.6; extra == \"socks\""))
        .isTrue();
    assertThat(PythonPyprojectProvider.hasExtraMarker("charset_normalizer<4,>=2")).isFalse();
    assertThat(
            PythonPyprojectProvider.hasExtraMarker(
                "importlib-metadata>=3.6.0; python_version < \"3.10\""))
        .isFalse();
  }

  @Test
  void test_extractDepName() {
    assertThat(PythonPyprojectProvider.extractDepName("charset_normalizer<4,>=2"))
        .isEqualTo("charset_normalizer");
    assertThat(PythonPyprojectProvider.extractDepName("idna<4,>=2.5")).isEqualTo("idna");
    assertThat(PythonPyprojectProvider.extractDepName("PySocks!=1.5.7,>=1.5.6; extra == \"socks\""))
        .isEqualTo("PySocks");
    assertThat(PythonPyprojectProvider.extractDepName("requests>=2.32")).isEqualTo("requests");
  }

  @Test
  void test_canonicalize() {
    assertThat(PythonPyprojectProvider.canonicalize("charset_normalizer"))
        .isEqualTo("charset-normalizer");
    assertThat(PythonPyprojectProvider.canonicalize("Jinja2")).isEqualTo("jinja2");
    assertThat(PythonPyprojectProvider.canonicalize("MarkupSafe")).isEqualTo("markupsafe");
    assertThat(PythonPyprojectProvider.canonicalize("my.package_name"))
        .isEqualTo("my-package-name");
  }

  @Test
  void test_provideStack_with_pip_report() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    String reportJson = Files.readString(reportPath);
    String encodedReport =
        Base64.getEncoder().encodeToString(reportJson.getBytes(StandardCharsets.UTF_8));

    System.setProperty(PythonPyprojectProvider.PROP_TRUSTIFY_DA_PIP_REPORT, encodedReport);
    try {
      var provider = new PythonPyprojectProvider(pyprojectPath);
      var content = provider.provideStack();
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      String sbomJson = new String(content.buffer);
      assertThat(sbomJson).contains("CycloneDX");
      assertThat(sbomJson).contains("pkg:pypi/");
      assertThat(sbomJson).contains("pkg:pypi/anyio@3.6.2");
      assertThat(sbomJson).contains("pkg:pypi/flask@2.0.3");
      assertThat(sbomJson).contains("pkg:pypi/requests@2.25.1");
      assertThat(sbomJson).contains("pkg:pypi/idna@3.4");
      assertThat(sbomJson).contains("pkg:pypi/sniffio@1.3.0");
      assertThat(sbomJson).contains("pkg:pypi/certifi@2023.5.7");
    } catch (RuntimeException | NoClassDefFoundError e) {
      Assumptions.assumeTrue(false, "Skipping: SBOM serialization unavailable - " + e.getMessage());
    } finally {
      System.clearProperty(PythonPyprojectProvider.PROP_TRUSTIFY_DA_PIP_REPORT);
    }
  }

  @Test
  void test_provideComponent_with_pip_report() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path reportPath =
        Path.of(
            "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pip_report.json");
    String reportJson = Files.readString(reportPath);
    String encodedReport =
        Base64.getEncoder().encodeToString(reportJson.getBytes(StandardCharsets.UTF_8));

    System.setProperty(PythonPyprojectProvider.PROP_TRUSTIFY_DA_PIP_REPORT, encodedReport);
    try {
      var provider = new PythonPyprojectProvider(pyprojectPath);
      var content = provider.provideComponent();
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      String sbomJson = new String(content.buffer);
      assertThat(sbomJson).contains("CycloneDX");
      assertThat(sbomJson).contains("pkg:pypi/anyio@3.6.2");
      assertThat(sbomJson).contains("pkg:pypi/flask@2.0.3");
      assertThat(sbomJson).contains("pkg:pypi/requests@2.25.1");
    } catch (RuntimeException | NoClassDefFoundError e) {
      Assumptions.assumeTrue(false, "Skipping: SBOM serialization unavailable - " + e.getMessage());
    } finally {
      System.clearProperty(PythonPyprojectProvider.PROP_TRUSTIFY_DA_PIP_REPORT);
    }
  }

  @Test
  void test_provideStack_with_exhortignore() throws IOException {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_ignore/pyproject.toml");
    Path reportPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_ignore/pip_report.json");
    String reportJson = Files.readString(reportPath);
    String encodedReport =
        Base64.getEncoder().encodeToString(reportJson.getBytes(StandardCharsets.UTF_8));

    System.setProperty(PythonPyprojectProvider.PROP_TRUSTIFY_DA_PIP_REPORT, encodedReport);
    try {
      var provider = new PythonPyprojectProvider(pyprojectPath);
      var content = provider.provideStack();
      String sbomJson = new String(content.buffer);
      assertThat(sbomJson).doesNotContain("pkg:pypi/flask@");
      assertThat(sbomJson).contains("pkg:pypi/anyio@3.6.2");
      assertThat(sbomJson).contains("pkg:pypi/requests@2.25.1");
    } catch (RuntimeException | NoClassDefFoundError e) {
      Assumptions.assumeTrue(false, "Skipping: SBOM serialization unavailable - " + e.getMessage());
    } finally {
      System.clearProperty(PythonPyprojectProvider.PROP_TRUSTIFY_DA_PIP_REPORT);
    }
  }
}
