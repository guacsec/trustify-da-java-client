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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.providers.javascript.model.Manifest;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.tools.Operations;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Concrete implementation of the Yarn Berry processor, supporting Yarn 2.x and later. */
public final class YarnBerryProcessor extends YarnProcessor {

  private static final Pattern LOCATOR_PATTERN = Pattern.compile("^(@?[^@]+(?:/[^@]+)?)@npm:(.+)$");
  private static final Pattern VIRTUAL_LOCATOR_PATTERN =
      Pattern.compile("^(@?[^@]+(?:/[^@]+)?)@virtual:[^#]+#npm:(.+)$");

  public YarnBerryProcessor(String packageManager, Manifest manifest) {
    super(packageManager, manifest);
  }

  @Override
  public String[] installCmd(Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager, "--cwd", manifestDir.toString(), "install", "--immutable"
      };
    }
    return new String[] {packageManager, "install", "--immutable"};
  }

  @Override
  public String[] listDepsCmd(boolean includeTransitive, Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager,
        "--cwd",
        manifestDir.toString(),
        "info",
        includeTransitive ? "--recursive" : "--all",
        "--json",
      };
    }
    return new String[] {
      packageManager, "info", includeTransitive ? "--recursive" : "--all", "--json",
    };
  }

  @Override
  protected Map<String, PackageURL> getRootDependencies(JsonNode depTree) {
    Map<String, PackageURL> rootDeps = new TreeMap<>();
    var nodes = (ArrayNode) depTree;
    if (nodes == null || nodes.isEmpty()) {
      return rootDeps;
    }

    for (JsonNode node : nodes) {
      var depName = node.get("value").asText();

      if (!isRoot(depName)) {
        var versionIdx = depName.lastIndexOf("@");
        var name = depName.substring(0, versionIdx);
        var version = node.get("children").get("Version").asText();
        rootDeps.put(name, JavaScriptProvider.toPurl(name, version));
      }
    }
    return rootDeps;
  }

  private boolean isRoot(String name) {
    return name.endsWith("@workspace:.");
  }

  @Override
  public String parseDepTreeOutput(String output) {
    return "["
        + output.trim().replaceAll(Operations.GENERIC_LINE_SEPARATOR, "").replace("}{", "},{")
        + "]";
  }

  private PackageURL purlFromNode(String normalizedLocator, JsonNode node) {
    var name = normalizedLocator.substring(0, normalizedLocator.lastIndexOf("@"));
    var version = node.get("children").get("Version").asText();
    return JavaScriptProvider.toPurl(name, version);
  }

  @Override
  void addDependenciesToSbom(Sbom sbom, JsonNode depTree) {
    if (depTree == null) {
      return;
    }
    depTree.forEach(
        n -> {
          var depName = n.get("value").asText();
          var from = isRoot(depName) ? sbom.getRoot() : purlFromNode(depName, n);
          var deps = (ArrayNode) n.get("children").get("Dependencies");
          if (deps != null && !deps.isEmpty()) {
            deps.forEach(
                d -> {
                  var target = purlFromlocator(d.get("locator").asText());
                  if (target != null) {
                    sbom.addDependency(from, target, null);
                  }
                });
          }
        });
  }

  private PackageURL purlFromlocator(String locator) {
    if (locator == null) return null;
    var matcher = LOCATOR_PATTERN.matcher(locator);
    if (matcher.matches()) {
      var name = matcher.group(1);
      var version = matcher.group(2);
      return JavaScriptProvider.toPurl(name, version);
    }
    matcher = VIRTUAL_LOCATOR_PATTERN.matcher(locator);
    if (matcher.matches()) {
      var name = matcher.group(1);
      var version = matcher.group(2);
      return JavaScriptProvider.toPurl(name, version);
    }
    return null;
  }
}
