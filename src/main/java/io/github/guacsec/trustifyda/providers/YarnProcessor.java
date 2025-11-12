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

import com.fasterxml.jackson.databind.JsonNode;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.providers.javascript.model.Manifest;
import io.github.guacsec.trustifyda.sbom.Sbom;
import java.nio.file.Path;
import java.util.Map;

/** Abstract implementation for the different Yarn versions */
public abstract class YarnProcessor {

  protected final String packageManager;
  protected final Manifest manifest;

  public YarnProcessor(String packageManager, Manifest manifest) {
    this.packageManager = packageManager;
    this.manifest = manifest;
  }

  abstract String[] installCmd(Path manifestDir);

  abstract String[] listDepsCmd(boolean includeTransitive, Path manifestDir);

  abstract Map<String, PackageURL> getRootDependencies(JsonNode depTree);

  abstract void addDependenciesToSbom(Sbom sbom, JsonNode depTree);

  public String parseDepTreeOutput(String output) {
    return output;
  }
}
