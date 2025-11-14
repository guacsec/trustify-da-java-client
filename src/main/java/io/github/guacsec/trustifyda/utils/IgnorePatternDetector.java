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

/**
 * Utility class for detecting ignore patterns in dependency manifests. Supports both legacy
 * 'exhortignore' and new 'trustify-da-ignore' patterns for backwards compatibility.
 */
public class IgnorePatternDetector {

  public static final String LEGACY_IGNORE_PATTERN = "exhortignore";
  public static final String IGNORE_PATTERN = "trustify-da-ignore";

  /**
   * Checks if a text line contains any ignore pattern (exhortignore or trustify-da-ignore). Used
   * for inline comment detection in requirements.txt, go.mod, build.gradle, etc.
   *
   * @param text the text to check
   * @return true if the text contains any ignore pattern
   */
  public static boolean containsIgnorePattern(String text) {
    return text.contains(LEGACY_IGNORE_PATTERN) || text.contains(IGNORE_PATTERN);
  }
}
