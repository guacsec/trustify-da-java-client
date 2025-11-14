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
package io.github.guacsec.trustifyda.providers.javascript.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.providers.JavaScriptProvider;
import io.github.guacsec.trustifyda.utils.IgnorePatternDetector;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class Manifest {

  public final String name;
  public final String version;
  public final PackageURL root;
  public final Set<String> dependencies;
  public final Set<String> ignored;
  public final Path path;

  public Manifest(Path manifestPath) throws IOException {
    this.path = manifestPath;
    if (manifestPath == null) {
      throw new IllegalArgumentException("Missing required manifestPath");
    }
    var content = loadManifest(manifestPath);
    this.dependencies = loadDependencies(content);
    this.name = content.get("name").asText();
    this.version = content.get("version").asText();
    this.root = JavaScriptProvider.toPurl(name, version);
    this.ignored = loadIgnored(content);
  }

  private JsonNode loadManifest(Path manifestPath) throws IOException {
    try (var is = Files.newInputStream(manifestPath)) {
      if (is == null) {
        throw new IllegalArgumentException("Unable to read required manifestPath: " + manifestPath);
      }
      return new ObjectMapper().readTree(Files.newInputStream(manifestPath));
    }
  }

  private Set<String> loadDependencies(JsonNode content) {
    var names = new HashSet<String>();
    if (content != null && content.has("dependencies")) {
      content.get("dependencies").fieldNames().forEachRemaining(names::add);
    }
    return Collections.unmodifiableSet(names);
  }

  private Set<String> loadIgnored(JsonNode content) {
    if (content == null) {
      return Collections.emptySet();
    }
    var node = content.get(IgnorePatternDetector.IGNORE_PATTERN);
    if (node == null || node.isEmpty()) {
      node = content.get(IgnorePatternDetector.LEGACY_IGNORE_PATTERN);
    }
    if (node != null && !node.isEmpty()) {
      var names = new HashSet<String>();
      node.forEach(n -> names.add(n.asText()));
      return Collections.unmodifiableSet(names);
    }
    return Collections.emptySet();
  }
}
