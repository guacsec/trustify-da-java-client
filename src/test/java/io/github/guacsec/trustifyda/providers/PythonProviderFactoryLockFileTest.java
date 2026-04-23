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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.ClearSystemProperty;

/**
 * Tests for PythonProviderFactory lock file walk-up. Verifies that the factory can find uv.lock in
 * parent directories for workspace member packages.
 */
class PythonProviderFactoryLockFileTest {

  private static final String PYPROJECT_TOML =
      "[project]\nname = \"my-lib\"\nversion = \"1.0.0\"\ndependencies = []\n";

  /** Lock file in manifest directory (existing behavior — fast path). */
  @Test
  void testLockFileInManifestDir(@TempDir Path tempDir) throws IOException {
    Files.writeString(tempDir.resolve("pyproject.toml"), PYPROJECT_TOML);
    Files.writeString(tempDir.resolve("uv.lock"), "version = 1");

    var provider = PythonProviderFactory.create(tempDir.resolve("pyproject.toml"));
    assertThat(provider).isInstanceOf(PythonUvProvider.class);
  }

  /** No lock file — falls back to pip provider. */
  @Test
  void testNoLockFileFallsToPip(@TempDir Path tempDir) throws IOException {
    Files.writeString(tempDir.resolve("pyproject.toml"), PYPROJECT_TOML);

    var provider = PythonProviderFactory.create(tempDir.resolve("pyproject.toml"));
    assertThat(provider).isInstanceOf(PythonPyprojectProvider.class);
  }

  /** Lock file at workspace root, member pyproject.toml in subdirectory. */
  @Test
  void testLockFileFoundInParentDir(@TempDir Path tempDir) throws IOException {
    // Workspace root with uv workspace config and lock file
    Files.writeString(
        tempDir.resolve("pyproject.toml"),
        "[project]\nname = \"workspace\"\nversion = \"1.0.0\"\n\n"
            + "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n");
    Files.writeString(tempDir.resolve("uv.lock"), "version = 1");

    // Member package without its own lock file
    Path memberDir = tempDir.resolve("packages/my-lib");
    Files.createDirectories(memberDir);
    Files.writeString(memberDir.resolve("pyproject.toml"), PYPROJECT_TOML);

    var provider = PythonProviderFactory.create(memberDir.resolve("pyproject.toml"));
    assertThat(provider).isInstanceOf(PythonUvProvider.class);
  }

  /** TRUSTIFY_DA_WORKSPACE_DIR overrides walk-up. */
  @Test
  @ClearSystemProperty(key = "TRUSTIFY_DA_WORKSPACE_DIR")
  void testWorkspaceDirOverride(@TempDir Path tempDir) throws IOException {
    // Custom dir with uv lock file
    Path customDir = tempDir.resolve("custom-root");
    Files.createDirectories(customDir);
    Files.writeString(customDir.resolve("uv.lock"), "version = 1");

    // Member without lock file
    Path memberDir = tempDir.resolve("packages/svc");
    Files.createDirectories(memberDir);
    Files.writeString(memberDir.resolve("pyproject.toml"), PYPROJECT_TOML);

    System.setProperty("TRUSTIFY_DA_WORKSPACE_DIR", customDir.toString());
    try {
      var provider = PythonProviderFactory.create(memberDir.resolve("pyproject.toml"));
      assertThat(provider).isInstanceOf(PythonUvProvider.class);
    } finally {
      System.clearProperty("TRUSTIFY_DA_WORKSPACE_DIR");
    }
  }

  /** Walk-up stops at uv workspace root boundary without lock file — falls back to pip. */
  @Test
  void testStopsAtUvWorkspaceRootBoundary(@TempDir Path tempDir) throws IOException {
    // Workspace root with uv workspace config but NO lock file
    Files.writeString(
        tempDir.resolve("pyproject.toml"),
        "[project]\nname = \"workspace\"\nversion = \"1.0.0\"\n\n"
            + "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n");

    // Member package
    Path memberDir = tempDir.resolve("packages/lib");
    Files.createDirectories(memberDir);
    Files.writeString(memberDir.resolve("pyproject.toml"), PYPROJECT_TOML);

    // Should fall back to pip, not keep walking up
    var provider = PythonProviderFactory.create(memberDir.resolve("pyproject.toml"));
    assertThat(provider).isInstanceOf(PythonPyprojectProvider.class);
  }

  /** validateLockFile passes for workspace member when uv.lock is in parent directory. */
  @Test
  void testValidateLockFilePassesWithLockInParent(@TempDir Path tempDir) throws IOException {
    // Workspace root with uv.lock
    Files.writeString(
        tempDir.resolve("pyproject.toml"),
        "[project]\nname = \"workspace\"\nversion = \"1.0.0\"\n\n"
            + "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n");
    Files.writeString(tempDir.resolve("uv.lock"), "version = 1");

    // Member package without its own lock file
    Path memberDir = tempDir.resolve("packages/my-lib");
    Files.createDirectories(memberDir);
    Files.writeString(memberDir.resolve("pyproject.toml"), PYPROJECT_TOML);

    var provider = new PythonUvProvider(memberDir.resolve("pyproject.toml"));
    // Ecosystem.getProvider() calls validateLockFile(manifestPath.getParent())
    assertThatCode(() -> provider.validateLockFile(memberDir)).doesNotThrowAnyException();
  }

  /** validateLockFile throws when uv.lock is not found anywhere. */
  @Test
  void testValidateLockFileThrowsWhenNotFound(@TempDir Path tempDir) throws IOException {
    Path memberDir = tempDir.resolve("packages/my-lib");
    Files.createDirectories(memberDir);
    Files.writeString(memberDir.resolve("pyproject.toml"), PYPROJECT_TOML);

    var provider = new PythonUvProvider(memberDir.resolve("pyproject.toml"));
    assertThatThrownBy(() -> provider.validateLockFile(memberDir))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("uv.lock does not exist");
  }
}
