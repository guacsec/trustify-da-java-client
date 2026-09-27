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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.guacsec.trustifyda.providers.javascript.model.Manifest;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.sbom.SbomFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Regression: a Yarn Berry workspace member reports its own node as
 * "&lt;name&gt;@workspace:packages/&lt;name&gt;", not "@workspace:.". isRoot must recognize the
 * member root so its dependencies land in the SBOM; otherwise the SBOM contained only the root
 * component (0 deps) and the backend reported no vulnerabilities for the member.
 */
class YarnBerryProcessorWorkspaceMemberTest {

  @Test
  void memberRootDependenciesAreIncludedInSbom(@TempDir Path tempDir) throws IOException {
    Path manifest = tempDir.resolve("package.json");
    Files.writeString(
        manifest,
        "{\"name\": \"pkg-a\", \"version\": \"1.0.0\", \"dependencies\": {\"axios\": \"1.6.0\"}}");

    var processor = new YarnBerryProcessor("yarn", new Manifest(manifest));

    // Member root node uses the "packages/<name>" resolution, plus its transitive dep node.
    var depTree =
        new ObjectMapper()
            .readTree(
                "[{\"value\":\"pkg-a@workspace:packages/pkg-a\",\"children\":{\"Version\":\"1.0.0\","
                    + "\"Dependencies\":[{\"descriptor\":\"axios@npm:1.6.0\",\"locator\":\"axios@npm:1.6.0\"}]}},"
                    + "{\"value\":\"axios@npm:1.6.0\",\"children\":{\"Version\":\"1.6.0\",\"Dependencies\":[]}}]");

    Sbom sbom = SbomFactory.newInstance();
    sbom.addRoot(new Manifest(manifest).root, null);
    processor.addDependenciesToSbom(sbom, depTree);

    assertThat(sbom.getAsJsonString()).contains("pkg:npm/axios@1.6.0");
  }
}
