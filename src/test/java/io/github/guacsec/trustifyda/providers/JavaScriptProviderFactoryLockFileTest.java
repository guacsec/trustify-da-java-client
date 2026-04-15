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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.ClearSystemProperty;

/**
 * Tests for JavaScriptProviderFactory lock file walk-up. Verifies that the factory can find lock
 * files in parent directories for workspace member packages.
 */
class JavaScriptProviderFactoryLockFileTest {

  /** Lock file in manifest directory (existing behavior — fast path). */
  @Test
  void testLockFileInManifestDir(@TempDir Path tempDir) throws IOException {
    Files.writeString(
        tempDir.resolve("package.json"), "{\"name\": \"app\", \"version\": \"1.0.0\"}");
    Files.writeString(tempDir.resolve("package-lock.json"), "{}");

    var provider = JavaScriptProviderFactory.create(tempDir.resolve("package.json"));
    assertThat(provider).isInstanceOf(JavaScriptNpmProvider.class);
  }

  /** Lock file at workspace root, member package.json in subdirectory. */
  @Test
  void testLockFileFoundInParentDir(@TempDir Path tempDir) throws IOException {
    // Workspace root with pnpm-workspace.yaml and lock file
    Files.writeString(tempDir.resolve("pnpm-workspace.yaml"), "packages:\n  - \"packages/*\"");
    Files.writeString(tempDir.resolve("pnpm-lock.yaml"), "lockfileVersion: '6.0'");

    // Member package without its own lock file
    Path memberDir = tempDir.resolve("packages/my-lib");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("package.json"), "{\"name\": \"@org/my-lib\", \"version\": \"1.0.0\"}");

    var provider = JavaScriptProviderFactory.create(memberDir.resolve("package.json"));
    assertThat(provider).isInstanceOf(JavaScriptPnpmProvider.class);
  }

  /** Yarn lock file at workspace root. */
  @Test
  void testYarnLockFileFoundInParent(@TempDir Path tempDir) throws IOException {
    Files.writeString(
        tempDir.resolve("package.json"),
        "{\"name\": \"monorepo\", \"version\": \"1.0.0\", \"workspaces\": [\"packages/*\"]}");
    Files.writeString(tempDir.resolve("yarn.lock"), "# yarn lockfile v1");

    Path memberDir = tempDir.resolve("packages/utils");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("package.json"), "{\"name\": \"@org/utils\", \"version\": \"2.0.0\"}");

    var provider = JavaScriptProviderFactory.create(memberDir.resolve("package.json"));
    assertThat(provider).isInstanceOf(JavaScriptYarnProvider.class);
  }

  /** No lock file anywhere — should throw. */
  @Test
  void testNoLockFileThrows(@TempDir Path tempDir) throws IOException {
    Path memberDir = tempDir.resolve("packages/app");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("package.json"), "{\"name\": \"app\", \"version\": \"1.0.0\"}");

    assertThatThrownBy(() -> JavaScriptProviderFactory.create(memberDir.resolve("package.json")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("No known lock file found");
  }

  /** TRUSTIFY_DA_WORKSPACE_DIR overrides walk-up. */
  @Test
  @ClearSystemProperty(key = "TRUSTIFY_DA_WORKSPACE_DIR")
  void testWorkspaceDirOverride(@TempDir Path tempDir) throws IOException {
    // Custom dir with npm lock file
    Path customDir = tempDir.resolve("custom-root");
    Files.createDirectories(customDir);
    Files.writeString(customDir.resolve("package-lock.json"), "{}");

    // Member without lock file
    Path memberDir = tempDir.resolve("packages/svc");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("package.json"), "{\"name\": \"svc\", \"version\": \"1.0.0\"}");

    System.setProperty("TRUSTIFY_DA_WORKSPACE_DIR", customDir.toString());
    try {
      var provider = JavaScriptProviderFactory.create(memberDir.resolve("package.json"));
      assertThat(provider).isInstanceOf(JavaScriptNpmProvider.class);
    } finally {
      System.clearProperty("TRUSTIFY_DA_WORKSPACE_DIR");
    }
  }

  /** Walk-up stops at workspace root boundary without lock file — should throw. */
  @Test
  void testStopsAtWorkspaceRootBoundary(@TempDir Path tempDir) throws IOException {
    // Workspace root with workspaces config but NO lock file
    Files.writeString(
        tempDir.resolve("package.json"),
        "{\"name\": \"monorepo\", \"version\": \"1.0.0\", \"workspaces\": [\"packages/*\"]}");

    // Member package
    Path memberDir = tempDir.resolve("packages/lib");
    Files.createDirectories(memberDir);
    Files.writeString(
        memberDir.resolve("package.json"), "{\"name\": \"@org/lib\", \"version\": \"1.0.0\"}");

    assertThatThrownBy(() -> JavaScriptProviderFactory.create(memberDir.resolve("package.json")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("No known lock file found");
  }
}
