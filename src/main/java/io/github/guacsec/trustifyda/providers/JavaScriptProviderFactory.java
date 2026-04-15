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

import io.github.guacsec.trustifyda.providers.javascript.workspace.JsWorkspaceDiscovery;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.Environment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Function;

/** Factory for creating the appropriate {@link JavaScriptProvider} based on lock file presence. */
public final class JavaScriptProviderFactory {

  private static final Map<String, Function<Path, JavaScriptProvider>> JS_PROVIDERS =
      Map.of(
          JavaScriptNpmProvider.LOCK_FILE, JavaScriptNpmProvider::new,
          JavaScriptYarnProvider.LOCK_FILE, JavaScriptYarnProvider::new,
          JavaScriptPnpmProvider.LOCK_FILE, JavaScriptPnpmProvider::new);

  /**
   * Creates a JavaScript provider by locating the lock file. Checks the manifest directory first,
   * then walks up parent directories to find the lock file at a workspace root.
   *
   * @param manifestPath the path to the package.json manifest
   * @return the matching JavaScript provider
   * @throws IllegalStateException if no supported lock file is found
   */
  public static JavaScriptProvider create(final Path manifestPath) {
    var manifestDir = manifestPath.getParent();

    // Check manifest directory first (fast path)
    for (var entry : JS_PROVIDERS.entrySet()) {
      var lockFilePath = manifestDir.resolve(entry.getKey());
      if (Files.isRegularFile(lockFilePath)) {
        return entry.getValue().apply(manifestPath);
      }
    }

    // Walk up parent directories to find lock file at workspace root
    Path lockFileDir = findLockFileDirInParents(manifestDir);
    if (lockFileDir != null) {
      for (var entry : JS_PROVIDERS.entrySet()) {
        if (Files.isRegularFile(lockFileDir.resolve(entry.getKey()))) {
          return entry.getValue().apply(manifestPath);
        }
      }
    }

    var validLockFiles = String.join(",", JS_PROVIDERS.keySet());
    throw new IllegalStateException(
        String.format(
            "No known lock file found for %s. Supported lock files: %s",
            manifestPath, validLockFiles));
  }

  private static Path findLockFileDirInParents(Path startDir) {
    // Environment override takes precedence
    String workspaceDirOverride = Environment.get("TRUSTIFY_DA_WORKSPACE_DIR");
    if (workspaceDirOverride != null && !workspaceDirOverride.isBlank()) {
      Path overrideDir = Path.of(workspaceDirOverride);
      for (String lockFile : JS_PROVIDERS.keySet()) {
        if (Files.isRegularFile(overrideDir.resolve(lockFile))) {
          return overrideDir;
        }
      }
      return null;
    }

    String gitRoot = Operations.getGitRootDir(startDir.toString()).orElse(null);
    Path boundary = gitRoot != null ? Path.of(gitRoot) : startDir.toAbsolutePath().getRoot();

    Path current = startDir.toAbsolutePath().normalize().getParent();
    while (current != null) {
      for (String lockFile : JS_PROVIDERS.keySet()) {
        if (Files.isRegularFile(current.resolve(lockFile))) {
          return current;
        }
      }

      // Stop at workspace root boundary
      if (JsWorkspaceDiscovery.isWorkspaceRoot(current)) {
        return null;
      }

      if (current.equals(boundary.toAbsolutePath().normalize())) {
        break;
      }

      current = current.getParent();
    }

    return null;
  }
}
