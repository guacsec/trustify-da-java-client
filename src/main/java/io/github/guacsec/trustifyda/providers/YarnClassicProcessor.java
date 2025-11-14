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
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/** Concrete implementation of the Yarn Classic processor, supporting Yarn 1.x */
public final class YarnClassicProcessor extends YarnProcessor {

  public YarnClassicProcessor(String packageManager, Manifest manifest) {
    super(packageManager, manifest);
  }

  @Override
  public String[] installCmd(Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager, "--cwd", manifestDir.toString(), "install", "--frozen-lockfile"
      };
    }
    return new String[] {packageManager, "install", "--frozen-lockfile"};
  }

  @Override
  public String[] listDepsCmd(boolean includeTransitive, Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager,
        "--cwd",
        manifestDir.toString(),
        "list",
        includeTransitive ? "--depth Infinity" : "--depth 0",
        "--prod",
        "--frozen-lockfile",
        "--json",
      };
    }
    return new String[] {
      packageManager,
      "list",
      includeTransitive ? "--depth Infinity" : "--depth 0",
      "--prod",
      "--frozen-lockfile",
      "--json",
    };
  }

  @Override
  Map<String, PackageURL> getRootDependencies(JsonNode depTree) {
    Map<String, PackageURL> rootDeps = new TreeMap<>();

    var data = depTree.get("data");
    if (data == null) {
      return rootDeps;
    }
    var trees = (ArrayNode) data.get("trees");
    if (trees == null) {
      return rootDeps;
    }
    trees.forEach(
        n -> {
          var depName = n.get("name").asText();
          var name = depName.substring(0, depName.lastIndexOf("@"));
          rootDeps.put(name, JavaScriptProvider.toPurl(depName));
        });
    return rootDeps;
  }

  @Override
  void addDependenciesToSbom(Sbom sbom, JsonNode depTree) {
    if (depTree == null || depTree.get("data") == null) {
      return;
    }
    var trees = (ArrayNode) depTree.get("data").get("trees");
    if (trees == null) {
      return;
    }
    Map<String, PackageURL> purls = new HashMap<>();
    trees.forEach(
        n -> {
          var dep = new NodeMetaData(n);

          purls.put(dep.name, dep.purl);
          if (manifest.dependencies.contains(dep.name)) {
            sbom.addDependency(manifest.root, dep.purl, null);
          }
        });

    trees.forEach(n -> addChildrenToSbom(sbom, n, purls));
  }

  void addChildrenToSbom(Sbom sbom, JsonNode node, Map<String, PackageURL> purls) {
    var dep = new NodeMetaData(node);
    var children = (ArrayNode) node.get("children");
    if (children != null) {
      children.forEach(
          c -> {
            var child = new NodeMetaData(c);
            var from = dep.shadow ? purls.get(dep.name) : dep.purl;
            var target = child.shadow ? purls.get(child.name) : child.purl;
            if (from != null && target != null) {
              sbom.addDependency(from, target, null);
            }
            addChildrenToSbom(sbom, c, purls);
          });
    }
  }

  private static class NodeMetaData {
    final String nodeName;
    final String name;
    final String version;
    final PackageURL purl;
    final boolean shadow;

    NodeMetaData(JsonNode node) {
      this.nodeName = node.get("name").asText();
      var versionIdx = nodeName.lastIndexOf("@");
      this.name = nodeName.substring(0, versionIdx);
      this.version = nodeName.substring(versionIdx + 1);
      this.purl = JavaScriptProvider.toPurl(name, version);
      var shadowNode = node.get("shadow");
      this.shadow = shadowNode != null && shadowNode.asBoolean();
    }
  }
}
