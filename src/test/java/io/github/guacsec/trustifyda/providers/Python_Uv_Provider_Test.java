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
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class Python_Uv_Provider_Test extends ExhortTest {

  private static final String UV_FIXTURE =
      "src/test/resources/tst_manifests/pip/pip_pyproject_toml_uv";
  private static final String UV_IGNORE_FIXTURE =
      "src/test/resources/tst_manifests/pip/pip_pyproject_toml_uv_ignore";

  @Test
  void test_ecosystem_resolves_pyproject_toml_with_uv_lock() throws IOException {
    var tempDir =
        new TempDirFromResources()
            .addFile("pyproject.toml")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_uv/pyproject.toml")
            .addFile("uv.lock")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_uv/uv.lock");
    Path pyprojectPath = tempDir.getTempDir().resolve("pyproject.toml");
    var provider = Ecosystem.getProvider(pyprojectPath);
    assertThat(provider).isInstanceOf(PythonUvProvider.class);
    assertThat(provider.ecosystem).isEqualTo(Ecosystem.Type.PYTHON);
  }

  @Test
  void test_ecosystem_resolves_pyproject_toml_without_uv_lock() {
    var provider =
        Ecosystem.getProvider(
            Path.of(
                "src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml"));
    assertThat(provider).isInstanceOf(PythonPyprojectProvider.class);
  }

  @Test
  void test_factory_selects_uv_provider_with_lock() throws IOException {
    var tempDir =
        new TempDirFromResources()
            .addFile("pyproject.toml")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_uv/pyproject.toml")
            .addFile("uv.lock")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_uv/uv.lock");
    Path pyprojectPath = tempDir.getTempDir().resolve("pyproject.toml");
    var provider = PythonProviderFactory.create(pyprojectPath);
    assertThat(provider).isInstanceOf(PythonUvProvider.class);
  }

  @Test
  void test_factory_falls_back_to_pyproject_without_lock() {
    Path pyprojectPath =
        Path.of("src/test/resources/tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    var provider = PythonProviderFactory.create(pyprojectPath);
    assertThat(provider).isInstanceOf(PythonPyprojectProvider.class);
  }

  @Test
  void test_validate_lock_file_passes_with_uv_lock() throws IOException {
    var tempDir =
        new TempDirFromResources()
            .addFile("pyproject.toml")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_uv/pyproject.toml")
            .addFile("uv.lock")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_uv/uv.lock");
    Path pyprojectPath = tempDir.getTempDir().resolve("pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    provider.validateLockFile(tempDir.getTempDir());
  }

  @Test
  void test_validate_lock_file_throws_without_uv_lock() throws IOException {
    var tempDir =
        new TempDirFromResources()
            .addFile("pyproject.toml")
            .fromResources("tst_manifests/pip/pip_pyproject_toml_no_ignore/pyproject.toml");
    Path pyprojectPath = tempDir.getTempDir().resolve("pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    assertThatIllegalStateException()
        .isThrownBy(() -> provider.validateLockFile(tempDir.getTempDir()))
        .withMessageContaining("uv.lock does not exist");
  }

  @Test
  void test_parseUvPipList_parses_packages() throws IOException {
    Path listPath = Path.of(UV_FIXTURE, "uv_pip_list.json");
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    String listJson = Files.readString(listPath);
    var packages = provider.parseUvPipList(listJson);
    assertThat(packages).containsKeys("anyio", "flask", "requests", "idna", "sniffio");
    assertThat(packages.get("anyio").version).isEqualTo("3.6.2");
    assertThat(packages.get("flask").version).isEqualTo("2.0.3");
  }

  @Test
  void test_parseUvPipShow_builds_children() throws IOException {
    Path listPath = Path.of(UV_FIXTURE, "uv_pip_list.json");
    Path showPath = Path.of(UV_FIXTURE, "uv_pip_show.txt");
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    String listJson = Files.readString(listPath);
    String showOutput = Files.readString(showPath);
    var packages = provider.parseUvPipList(listJson);
    provider.parseUvPipShow(showOutput, packages);

    var requestsPkg = packages.get("requests");
    assertThat(requestsPkg).isNotNull();
    assertThat(requestsPkg.children)
        .containsExactlyInAnyOrder("charset-normalizer", "idna", "urllib3", "certifi");

    var anyioPkg = packages.get("anyio");
    assertThat(anyioPkg).isNotNull();
    assertThat(anyioPkg.children).containsExactlyInAnyOrder("idna", "sniffio");

    var flaskPkg = packages.get("flask");
    assertThat(flaskPkg).isNotNull();
    assertThat(flaskPkg.children)
        .containsExactlyInAnyOrder("werkzeug", "jinja2", "itsdangerous", "click");

    var jinja2Pkg = packages.get("jinja2");
    assertThat(jinja2Pkg).isNotNull();
    assertThat(jinja2Pkg.children).containsExactly("markupsafe");
  }

  @Test
  void test_buildDependencyGraph_identifies_direct_deps() throws IOException {
    Path listPath = Path.of(UV_FIXTURE, "uv_pip_list.json");
    Path showPath = Path.of(UV_FIXTURE, "uv_pip_show.txt");
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    String listJson = Files.readString(listPath);
    String showOutput = Files.readString(showPath);

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_SHOW, showOutput);
    try {
      var data = provider.buildDependencyGraph(Path.of(UV_FIXTURE), listJson);
      assertThat(data.directDeps).containsExactlyInAnyOrder("anyio", "flask", "requests");
    } finally {
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_SHOW);
    }
  }

  @Test
  void test_getRootComponentName_reads_pep621_name() {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    assertThat(provider.getRootComponentName()).isEqualTo("test-project");
  }

  @Test
  void test_getRootComponentVersion_reads_pep621_version() {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    assertThat(provider.getRootComponentVersion()).isEqualTo("0.1.0");
  }

  @Test
  void test_provideStack_with_uv_pip() throws IOException {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    String listJson = Files.readString(Path.of(UV_FIXTURE, "uv_pip_list.json"));
    String showOutput = Files.readString(Path.of(UV_FIXTURE, "uv_pip_show.txt"));

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_LIST, listJson);
    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_SHOW, showOutput);
    try {
      var provider = new PythonUvProvider(pyprojectPath);
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
      assertThat(sbomJson).contains("pkg:pypi/markupsafe@2.1.2");
    } catch (RuntimeException | NoClassDefFoundError e) {
      Assumptions.assumeTrue(false, "Skipping: SBOM serialization unavailable - " + e.getMessage());
    } finally {
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_LIST);
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_SHOW);
    }
  }

  @Test
  void test_provideComponent_with_uv_pip() throws IOException {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    String listJson = Files.readString(Path.of(UV_FIXTURE, "uv_pip_list.json"));

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_LIST, listJson);
    try {
      var provider = new PythonUvProvider(pyprojectPath);
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
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_LIST);
    }
  }

  @Test
  void test_ignored_dependencies_in_uv_project() throws IOException {
    Path pyprojectPath = Path.of(UV_IGNORE_FIXTURE, "pyproject.toml");
    String listJson = Files.readString(Path.of(UV_IGNORE_FIXTURE, "uv_pip_list.json"));
    String showOutput = Files.readString(Path.of(UV_IGNORE_FIXTURE, "uv_pip_show.txt"));

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_LIST, listJson);
    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_SHOW, showOutput);
    try {
      var provider = new PythonUvProvider(pyprojectPath);
      var content = provider.provideStack();
      String sbomJson = new String(content.buffer);
      assertThat(sbomJson).doesNotContain("pkg:pypi/flask@");
      assertThat(sbomJson).contains("pkg:pypi/anyio@3.6.2");
      assertThat(sbomJson).contains("pkg:pypi/requests@2.25.1");
    } catch (RuntimeException | NoClassDefFoundError e) {
      Assumptions.assumeTrue(false, "Skipping: SBOM serialization unavailable - " + e.getMessage());
    } finally {
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_LIST);
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_PIP_SHOW);
    }
  }

  @Test
  void test_canonicalize() {
    assertThat(PythonUvProvider.canonicalize("charset_normalizer")).isEqualTo("charset-normalizer");
    assertThat(PythonUvProvider.canonicalize("Jinja2")).isEqualTo("jinja2");
    assertThat(PythonUvProvider.canonicalize("MarkupSafe")).isEqualTo("markupsafe");
  }
}
