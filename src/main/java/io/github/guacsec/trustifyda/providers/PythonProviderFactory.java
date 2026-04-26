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

import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.Environment;
import io.github.guacsec.trustifyda.utils.PyprojectTomlUtils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Function;

/**
 * Factory for creating the appropriate {@link PythonProvider} based on lock file presence. Follows
 * the same pattern as {@link JavaScriptProviderFactory}.
 */
public final class PythonProviderFactory {

  private static final Map<String, Function<Path, PythonProvider>> PYTHON_PROVIDERS =
      Map.of(PythonUvProvider.LOCK_FILE, PythonUvProvider::new);

  /**
   * Creates a Python provider for {@code pyproject.toml} manifests by checking for known lock files
   * in the manifest directory and parent directories (for workspace members). When {@code uv.lock}
   * is present, returns a {@link PythonUvProvider}; otherwise falls back to {@link
   * PythonPyprojectProvider} (pip-based).
   *
   * @param manifestPath the path to the pyproject.toml manifest
   * @return the matching Python provider
   */
  public static PythonProvider create(final Path manifestPath) {
    var manifestDir = manifestPath.getParent();

    // Check manifest directory first (fast path)
    for (var entry : PYTHON_PROVIDERS.entrySet()) {
      if (Files.isRegularFile(manifestDir.resolve(entry.getKey()))) {
        return entry.getValue().apply(manifestPath);
      }
    }

    // Walk up parent directories to find lock file at workspace root
    Path lockFileDir = findLockFileDirInParents(manifestDir);
    if (lockFileDir != null) {
      for (var entry : PYTHON_PROVIDERS.entrySet()) {
        if (Files.isRegularFile(lockFileDir.resolve(entry.getKey()))) {
          return entry.getValue().apply(manifestPath);
        }
      }
    }

    // Unlike JavaScript, pip fallback is valid — no lock file required
    return new PythonPyprojectProvider(manifestPath);
  }

  /**
   * Walks up from the given directory to find a parent containing a known Python lock file.
   * Respects {@code TRUSTIFY_DA_WORKSPACE_DIR} override, stops at uv workspace root boundaries and
   * the git root.
   *
   * @param startDir the directory to start searching from (typically the manifest directory)
   * @return the directory containing the lock file, or {@code null} if not found
   */
  static Path findLockFileDirInParents(Path startDir) {
    // Environment override takes precedence
    String workspaceDirOverride = Environment.get("TRUSTIFY_DA_WORKSPACE_DIR");
    if (workspaceDirOverride != null && !workspaceDirOverride.isBlank()) {
      Path overrideDir = Path.of(workspaceDirOverride);
      for (String lockFile : PYTHON_PROVIDERS.keySet()) {
        if (Files.isRegularFile(overrideDir.resolve(lockFile))) {
          return overrideDir;
        }
      }
      return null;
    }

    // If startDir itself is a workspace root, don't walk up to avoid escaping into a parent
    // workspace
    if (PyprojectTomlUtils.isUvWorkspaceRoot(startDir)) {
      return null;
    }

    String gitRoot = Operations.getGitRootDir(startDir.toString()).orElse(null);
    Path boundary = gitRoot != null ? Path.of(gitRoot) : startDir.toAbsolutePath().getRoot();

    Path current = startDir.toAbsolutePath().normalize().getParent();
    while (current != null) {
      for (String lockFile : PYTHON_PROVIDERS.keySet()) {
        if (Files.isRegularFile(current.resolve(lockFile))) {
          return current;
        }
      }

      // Stop at uv workspace root boundary
      if (PyprojectTomlUtils.isUvWorkspaceRoot(current)) {
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
