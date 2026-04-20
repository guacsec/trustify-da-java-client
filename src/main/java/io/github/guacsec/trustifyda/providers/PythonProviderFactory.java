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
   * in the manifest directory. When {@code uv.lock} is present, returns a {@link PythonUvProvider};
   * otherwise falls back to {@link PythonPyprojectProvider} (pip-based).
   *
   * @param manifestPath the path to the pyproject.toml manifest
   * @return the matching Python provider
   */
  public static PythonProvider create(final Path manifestPath) {
    var manifestDir = manifestPath.getParent();

    for (var entry : PYTHON_PROVIDERS.entrySet()) {
      if (Files.isRegularFile(manifestDir.resolve(entry.getKey()))) {
        return entry.getValue().apply(manifestPath);
      }
    }

    // Unlike JavaScript, pip fallback is valid — no lock file required
    return new PythonPyprojectProvider(manifestPath);
  }
}
