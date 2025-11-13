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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class IgnorePatternDetectorTest {

  @Test
  void testContainsIgnorePattern() {
    // Test legacy exhortignore
    assertTrue(IgnorePatternDetector.containsIgnorePattern("some line //exhortignore"));
    assertTrue(IgnorePatternDetector.containsIgnorePattern("exhortignore"));

    // Test new trustify-da-ignore
    assertTrue(IgnorePatternDetector.containsIgnorePattern("some line //trustify-da-ignore"));
    assertTrue(IgnorePatternDetector.containsIgnorePattern("trustify-da-ignore"));

    // Test negative cases
    assertFalse(IgnorePatternDetector.containsIgnorePattern("normal line"));
    assertFalse(IgnorePatternDetector.containsIgnorePattern("ignore but not the right pattern"));
  }

  @Test
  void testIsIgnoreComment() {
    // Test legacy exhortignore
    assertTrue(IgnorePatternDetector.isIgnoreComment("exhortignore"));
    assertTrue(IgnorePatternDetector.isIgnoreComment("  exhortignore  "));

    // Test new trustify-da-ignore
    assertTrue(IgnorePatternDetector.isIgnoreComment("trustify-da-ignore"));
    assertTrue(IgnorePatternDetector.isIgnoreComment("  trustify-da-ignore  "));

    // Test negative cases
    assertFalse(IgnorePatternDetector.isIgnoreComment("not an ignore comment"));
    assertFalse(IgnorePatternDetector.isIgnoreComment("exhortignore extra"));
    assertFalse(IgnorePatternDetector.isIgnoreComment("prefix exhortignore"));
  }

  @Test
  void testContainsPythonIgnorePattern() {
    // Test legacy exhortignore patterns
    assertTrue(IgnorePatternDetector.containsPythonIgnorePattern("package==1.0 #exhortignore"));
    assertTrue(IgnorePatternDetector.containsPythonIgnorePattern("package==1.0 # exhortignore"));

    // Test new trustify-da-ignore patterns
    assertTrue(
        IgnorePatternDetector.containsPythonIgnorePattern("package==1.0 #trustify-da-ignore"));
    assertTrue(
        IgnorePatternDetector.containsPythonIgnorePattern("package==1.0 # trustify-da-ignore"));

    // Test negative cases
    assertFalse(IgnorePatternDetector.containsPythonIgnorePattern("package==1.0"));
    assertFalse(
        IgnorePatternDetector.containsPythonIgnorePattern("package==1.0 # some other comment"));
  }
}
