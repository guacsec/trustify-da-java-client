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

import java.util.Map;
import org.junit.jupiter.api.Test;

class GoModulesParseModuleVersionsTest {

  @Test
  void parseStandardModuleLines() {
    String input = "github.com/foo/bar v1.2.3\ngithub.com/baz/qux v0.1.0\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result)
        .containsEntry("github.com/foo/bar", "v1.2.3")
        .containsEntry("github.com/baz/qux", "v0.1.0")
        .hasSize(2);
  }

  @Test
  void parseReplaceDirectiveLines() {
    String input = "github.com/old/mod v1.0.0 => github.com/new/mod v2.0.0\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result).containsEntry("github.com/old/mod", "v2.0.0").hasSize(1);
  }

  @Test
  void parseWithMultipleSpacesAndTabs() {
    String input = "github.com/foo/bar   v1.2.3\ngithub.com/baz/qux\tv0.1.0\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result)
        .containsEntry("github.com/foo/bar", "v1.2.3")
        .containsEntry("github.com/baz/qux", "v0.1.0")
        .hasSize(2);
  }

  @Test
  void parseWithBlankAndWhitespaceOnlyLines() {
    String input = "\n  \ngithub.com/foo/bar v1.0.0\n\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result).containsEntry("github.com/foo/bar", "v1.0.0").hasSize(1);
  }

  @Test
  void parseSkipsMalformedLines() {
    String input = "github.com/foo/bar v1.0.0\nsingle-token\nthree tokens here\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result).containsEntry("github.com/foo/bar", "v1.0.0").hasSize(1);
  }

  @Test
  void parseEmptyInput() {
    Map<String, String> result = GoModulesProvider.parseModuleVersions("");
    assertThat(result).isEmpty();
  }

  @Test
  void parseReplaceDirectiveWithTabSeparation() {
    String input = "github.com/old/mod\tv1.0.0\t=>\tgithub.com/new/mod\tv2.0.0\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result).containsEntry("github.com/old/mod", "v2.0.0").hasSize(1);
  }

  @Test
  void parseDuplicateModuleKeepsLast() {
    String input = "github.com/foo/bar v1.0.0\ngithub.com/foo/bar v2.0.0\n";
    Map<String, String> result = GoModulesProvider.parseModuleVersions(input);
    assertThat(result).containsEntry("github.com/foo/bar", "v2.0.0").hasSize(1);
  }
}
