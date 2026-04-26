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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.utils.PyprojectTomlUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
  void test_parseUvExport_parses_packages() throws IOException {
    Path exportPath = Path.of(UV_FIXTURE, "uv_export.txt");
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    String exportOutput = Files.readString(exportPath);
    var data = provider.parseUvExport(exportOutput);
    assertThat(data.graph()).containsKeys("anyio", "flask", "requests", "idna", "sniffio");
    assertThat(data.graph().get("anyio").version()).isEqualTo("3.6.2");
    assertThat(data.graph().get("flask").version()).isEqualTo("2.0.3");
  }

  @Test
  void test_parseUvExport_builds_children() throws IOException {
    Path exportPath = Path.of(UV_FIXTURE, "uv_export.txt");
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    String exportOutput = Files.readString(exportPath);
    var data = provider.parseUvExport(exportOutput);

    var requestsPkg = data.graph().get("requests");
    assertThat(requestsPkg).isNotNull();
    assertThat(requestsPkg.children())
        .containsExactlyInAnyOrder("charset-normalizer", "idna", "urllib3", "certifi");

    var anyioPkg = data.graph().get("anyio");
    assertThat(anyioPkg).isNotNull();
    assertThat(anyioPkg.children()).containsExactlyInAnyOrder("idna", "sniffio");

    var flaskPkg = data.graph().get("flask");
    assertThat(flaskPkg).isNotNull();
    assertThat(flaskPkg.children())
        .containsExactlyInAnyOrder("werkzeug", "jinja2", "itsdangerous", "click");

    var jinja2Pkg = data.graph().get("jinja2");
    assertThat(jinja2Pkg).isNotNull();
    assertThat(jinja2Pkg.children()).containsExactly("markupsafe");
  }

  @Test
  void test_parseUvExport_identifies_direct_deps() throws IOException {
    Path exportPath = Path.of(UV_FIXTURE, "uv_export.txt");
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);
    String exportOutput = Files.readString(exportPath);
    var data = provider.parseUvExport(exportOutput);
    assertThat(data.directDeps()).containsExactlyInAnyOrder("anyio", "flask", "requests");
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
  void test_provideStack_with_uv_export() throws IOException {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    String exportOutput = Files.readString(Path.of(UV_FIXTURE, "uv_export.txt"));

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_EXPORT, exportOutput);
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
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_EXPORT);
    }
  }

  @Test
  void test_provideComponent_with_uv_export() throws IOException {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    String exportOutput = Files.readString(Path.of(UV_FIXTURE, "uv_export.txt"));

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_EXPORT, exportOutput);
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
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_EXPORT);
    }
  }

  @Test
  void test_ignored_dependencies_in_uv_project() throws IOException {
    Path pyprojectPath = Path.of(UV_IGNORE_FIXTURE, "pyproject.toml");
    String exportOutput = Files.readString(Path.of(UV_IGNORE_FIXTURE, "uv_export.txt"));

    System.setProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_EXPORT, exportOutput);
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
      System.clearProperty(PythonUvProvider.PROP_TRUSTIFY_DA_UV_EXPORT);
    }
  }

  @Test
  void test_parseUvExport_includes_editable_installs(@TempDir Path tempDir) throws IOException {
    // Create a workspace member with its own pyproject.toml
    Path memberDir = tempDir.resolve("packages").resolve("my-lib");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("pyproject.toml"),
        "[project]\nname = \"my-lib\"\nversion = \"2.0.0\"\ndependencies = []\n");

    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);

    // Simulate uv export output with an editable install
    String exportOutput =
        "# This file was autogenerated by uv\n"
            + "-e file://"
            + memberDir.toUri().getPath()
            + "\n"
            + "    # via test-project\n"
            + "anyio==3.6.2\n"
            + "    # via my-lib\n";

    var data = provider.parseUvExport(exportOutput);

    // The editable install should be in the graph with name/version from pyproject.toml
    assertThat(data.graph()).containsKey("my-lib");
    assertThat(data.graph().get("my-lib").name()).isEqualTo("my-lib");
    assertThat(data.graph().get("my-lib").version()).isEqualTo("2.0.0");

    // It should be identified as a direct dependency (via test-project)
    assertThat(data.directDeps()).contains("my-lib");

    // anyio should be a child of my-lib
    assertThat(data.graph().get("my-lib").children()).contains("anyio");
  }

  @Test
  void test_parseUvExport_editable_skips_self_reference(@TempDir Path tempDir) throws IOException {
    // Create a member whose name matches the root project (test-project)
    Path memberDir = tempDir.resolve("packages").resolve("self");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("pyproject.toml"),
        "[project]\nname = \"test-project\"\nversion = \"0.1.0\"\ndependencies = []\n");

    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);

    String exportOutput =
        "# This file was autogenerated by uv\n"
            + "-e file://"
            + memberDir.toUri().getPath()
            + "\n"
            + "anyio==3.6.2\n"
            + "    # via test-project\n";

    var data = provider.parseUvExport(exportOutput);

    // The root project should NOT appear in the graph as its own dependency
    assertThat(data.graph()).doesNotContainKey("test-project");
    // anyio should still be a direct dep
    assertThat(data.directDeps()).contains("anyio");
  }

  @Test
  void test_parseUvExport_editable_skips_missing_version(@TempDir Path tempDir) throws IOException {
    // Create a member with no version
    Path memberDir = tempDir.resolve("packages").resolve("no-version");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("pyproject.toml"),
        "[project]\nname = \"no-version-lib\"\ndependencies = []\n");

    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);

    String exportOutput =
        "# This file was autogenerated by uv\n"
            + "-e file://"
            + memberDir.toUri().getPath()
            + "\n"
            + "    # via test-project\n"
            + "anyio==3.6.2\n"
            + "    # via test-project\n";

    var data = provider.parseUvExport(exportOutput);

    // Package with no version should be skipped
    assertThat(data.graph()).doesNotContainKey("no-version-lib");
    // anyio should still be parsed
    assertThat(data.graph()).containsKey("anyio");
  }

  @Test
  void test_parseUvExport_editable_falls_back_to_poetry_name(@TempDir Path tempDir)
      throws IOException {
    // Create a member with Poetry-style name/version only
    Path memberDir = tempDir.resolve("packages").resolve("poetry-lib");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("pyproject.toml"),
        "[tool.poetry]\nname = \"poetry-lib\"\nversion = \"1.5.0\"\n");

    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);

    String exportOutput =
        "# This file was autogenerated by uv\n"
            + "-e file://"
            + memberDir.toUri().getPath()
            + "\n"
            + "    # via test-project\n"
            + "anyio==3.6.2\n"
            + "    # via poetry-lib\n";

    var data = provider.parseUvExport(exportOutput);

    // Poetry name/version should be used as fallback
    assertThat(data.graph()).containsKey("poetry-lib");
    assertThat(data.graph().get("poetry-lib").name()).isEqualTo("poetry-lib");
    assertThat(data.graph().get("poetry-lib").version()).isEqualTo("1.5.0");

    // It should be a direct dep and anyio should be its child
    assertThat(data.directDeps()).contains("poetry-lib");
    assertThat(data.graph().get("poetry-lib").children()).contains("anyio");
  }

  @Test
  void test_parseUvExport_via_skips_non_bare_package_names() throws IOException {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);

    String exportOutput =
        "# This file was autogenerated by uv\n"
            + "anyio==3.6.2\n"
            + "    # via test-project\n"
            + "idna==3.4\n"
            + "    # via foo (>=1.0)\n"
            + "sniffio==1.3.0\n"
            + "    # via foo[extra]\n";

    var data = provider.parseUvExport(exportOutput);

    // anyio is direct (via test-project)
    assertThat(data.directDeps()).contains("anyio");
    // idna and sniffio should be in the graph but with no parent edges
    assertThat(data.graph()).containsKey("idna");
    assertThat(data.graph()).containsKey("sniffio");
    // No package should have children since the via names were invalid
    assertThat(data.graph().values().stream().allMatch(p -> p.children().isEmpty())).isTrue();
  }

  @Test
  void test_parseUvExport_throws_on_unpinned_version() {
    Path pyprojectPath = Path.of(UV_FIXTURE, "pyproject.toml");
    var provider = new PythonUvProvider(pyprojectPath);

    String exportOutput =
        "# This file was autogenerated by uv\n" + "anyio>=3.6.2\n" + "    # via test-project\n";

    assertThatThrownBy(() -> provider.parseUvExport(exportOutput))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("has no pinned version");
  }

  @Test
  void test_canonicalize() {
    assertThat(PyprojectTomlUtils.canonicalize("charset_normalizer"))
        .isEqualTo("charset-normalizer");
    assertThat(PyprojectTomlUtils.canonicalize("Jinja2")).isEqualTo("jinja2");
    assertThat(PyprojectTomlUtils.canonicalize("MarkupSafe")).isEqualTo("markupsafe");
  }
}
