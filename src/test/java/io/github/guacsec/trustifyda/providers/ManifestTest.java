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

import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.providers.javascript.model.Manifest;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ManifestTest extends ExhortTest {

  @Test
  void loads_manifest_with_mixed_dependency_types() throws IOException {
    var manifestPath = resolveFile("tst_manifests/npm/deps_with_mixed_dep_types/package.json");
    var m = new Manifest(manifestPath);

    assertThat(m.name).isEqualTo("mixed-deps-test");
    assertThat(m.version).isEqualTo("1.0.0");

    // dependencies should include deps, peerDeps, and optionalDeps but NOT devDeps
    assertThat(m.dependencies).containsExactlyInAnyOrder("express", "axios", "minimist", "lodash");
    assertThat(m.dependencies).doesNotContain("jest", "eslint");

    // peerDependencies and optionalDependencies maps
    assertThat(m.peerDependencies).isEqualTo(Map.of("minimist", "1.2.0"));
    assertThat(m.optionalDependencies).isEqualTo(Map.of("lodash", "4.17.19"));

    assertThat(m.ignored).isEmpty();
  }
}
