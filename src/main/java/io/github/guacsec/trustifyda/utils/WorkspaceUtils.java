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
package io.github.guacsec.trustifyda.utils;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.List;
import java.util.Set;

/**
 * Shared workspace utilities used by both JS and Cargo workspace discovery.
 */
public final class WorkspaceUtils {

  private WorkspaceUtils() {}

  /**
   * Filters manifest paths by ignore patterns.
   *
   * @param workspaceDir the workspace root directory used to relativize paths
   * @param manifests the manifest paths to filter
   * @param ignorePatterns glob patterns for paths to exclude
   * @return filtered list of manifest paths
   */
  public static List<Path> filterByIgnorePatterns(
      Path workspaceDir, List<Path> manifests, Set<String> ignorePatterns) {
    if (ignorePatterns == null || ignorePatterns.isEmpty()) {
      return manifests;
    }

    List<PathMatcher> matchers =
        ignorePatterns.stream()
            .map(p -> FileSystems.getDefault().getPathMatcher("glob:" + p))
            .toList();

    return manifests.stream()
        .filter(
            manifest -> {
              Path relative = workspaceDir.relativize(manifest);
              if (relative.toString().isEmpty()) {
                return true;
              }
              Path relativeDir = relative.getParent();
              return matchers.stream()
                  .noneMatch(
                      m -> m.matches(relative) || (relativeDir != null && m.matches(relativeDir)));
            })
        .toList();
  }
}
