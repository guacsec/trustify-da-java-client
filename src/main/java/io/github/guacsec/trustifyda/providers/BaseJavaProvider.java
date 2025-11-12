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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public abstract class BaseJavaProvider extends Provider {

  protected BaseJavaProvider(Ecosystem.Type ecosystem, Path manifest) {
    super(ecosystem, manifest);
  }

  void parseDependencyTree(String src, int srcDepth, String[] lines, Sbom sbom, String scope) {
    if (lines.length == 0) {
      return;
    }
    if (lines.length == 1 && lines[0].trim().isEmpty()) {
      return;
    }
    int index = 0;
    String target = lines[index];
    int targetDepth = getDepth(target);
    while (targetDepth > srcDepth && index < lines.length) {
      if (targetDepth == srcDepth + 1) {
        PackageURL from = parseDep(src);
        PackageURL to = parseDep(target);
        if (dependencyIsNotTestScope(from) && dependencyIsNotTestScope(to)) {
          sbom.addDependency(from, to, scope);
        }
      } else {
        String[] modifiedLines = Arrays.copyOfRange(lines, index, lines.length);
        parseDependencyTree(
            lines[index - 1], getDepth(lines[index - 1]), modifiedLines, sbom, scope);
      }
      if (index < lines.length - 1) {
        target = lines[++index];
        targetDepth = getDepth(target);
      } else {
        index++;
      }
    }
  }

  static boolean dependencyIsNotTestScope(PackageURL artifact) {
    return (Objects.nonNull(artifact.getQualifiers())
            && !artifact.getQualifiers().get("scope").equals("test"))
        || Objects.isNull(artifact.getQualifiers());
  }

  PackageURL parseDep(String dep) {
    // root package
    DependencyAggregator dependencyAggregator = new DependencyAggregator();
    // in case line in dependency tree text starts with a letter ( for root artifact).
    if (dep.matches("^\\w.*")) {
      dependencyAggregator = new DependencyAggregator();
      String[] parts = dep.split(":");
      dependencyAggregator.groupId = parts[0];
      dependencyAggregator.artifactId = parts[1];
      dependencyAggregator.version = parts[3];

      return dependencyAggregator.toPurl();
    }
    int firstDash = dep.indexOf("-");
    String dependency = dep.substring(++firstDash).trim();
    if (dependency.startsWith("(")) {
      dependency = dependency.substring(1);
    }
    dependency = dependency.replace(":runtime", ":compile").replace(":provided", ":compile");
    int endIndex = Math.max(dependency.indexOf(":compile"), dependency.indexOf(":test"));
    int scopeLength;
    if (dependency.contains(":compile")) {
      scopeLength = ":compile".length();
    } else {
      scopeLength = ":test".length();
    }
    dependency = dependency.substring(0, endIndex + scopeLength);
    String[] parts = dependency.split(":");
    // contains only GAV + packaging + scope
    if (parts.length == 5) {
      dependencyAggregator.groupId = parts[0];
      dependencyAggregator.artifactId = parts[1];
      dependencyAggregator.version = parts[3];

      String conflictMessage = "omitted for conflict with";
      if (dep.contains(conflictMessage)) {
        dependencyAggregator.version =
            dep.substring(dep.indexOf(conflictMessage) + conflictMessage.length())
                .replace(")", "")
                .trim();
      }
    }
    // In case there are 6 parts, there is also a classifier for artifact (version suffix)
    // contains GAV + packaging + classifier + scope
    else if (parts.length == 6) {
      dependencyAggregator.groupId = parts[0];
      dependencyAggregator.artifactId = parts[1];
      dependencyAggregator.version = String.format("%s-%s", parts[4], parts[3]);
      String conflictMessage = "omitted for conflict with";
      if (dep.contains(conflictMessage)) {
        dependencyAggregator.version =
            dep.substring(dep.indexOf(conflictMessage) + conflictMessage.length())
                .replace(")", "")
                .trim();
      }

    } else {
      throw new RuntimeException(
          String.format("Cannot parse dependency into PackageUrl from line = \"%s\"", dep));
    }
    if (parts[parts.length - 1].matches(".*[a-z]$")) {
      dependencyAggregator.scope = parts[parts.length - 1];
    } else {
      int endOfLine =
          Integer.min(parts[parts.length - 1].indexOf(""), parts[parts.length - 1].indexOf("-"));
      dependencyAggregator.scope = parts[parts.length - 1].substring(0, endOfLine).trim();
    }
    return dependencyAggregator.toPurl();
  }

  int getDepth(String line) {
    if (line == null || line.trim().isEmpty()) {
      return -1;
    }

    if (line.matches("^\\w.*")) {
      return 0;
    }

    return ((line.indexOf('-') - 1) / 3) + 1;
  }

  // NOTE if we want to include "scope" tags in ignore,
  // add property here and a case in the start-element-switch in the getIgnored method

  /** Aggregator class for aggregating Dependency data over stream iterations, */
  static final class DependencyAggregator {
    String scope = "*";
    String groupId;
    String artifactId;
    String version;
    boolean ignored = false;

    /**
     * Get the string representation of the dependency to use as excludes
     *
     * @return an exclude string for the dependency:tree plugin, i.e. group-id:artifact-id:*:version
     */
    @Override
    public String toString() {
      // NOTE if you add scope, don't forget to replace the * with its value
      return String.format("%s:%s:%s:%s", groupId, artifactId, scope, version);
    }

    boolean isValid() {
      return Objects.nonNull(groupId) && Objects.nonNull(artifactId) && Objects.nonNull(version);
    }

    boolean isTestDependency() {
      return scope.trim().equals("test");
    }

    PackageURL toPurl() {
      try {
        return new PackageURL(
            Ecosystem.Type.MAVEN.getType(),
            groupId,
            artifactId,
            version,
            this.scope.equals("*") ? null : new TreeMap<>(Map.of("scope", this.scope)),
            null);
      } catch (MalformedPackageURLException e) {
        throw new IllegalArgumentException("Unable to parse PackageURL", e);
      }
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof DependencyAggregator)) return false;
      var that = (DependencyAggregator) o;
      // NOTE we do not compare the ignored field
      // This is required for comparing pom.xml with effective_pom.xml as the latter doesn't
      // contain comments indicating ignore
      return Objects.equals(this.groupId, that.groupId)
          && Objects.equals(this.artifactId, that.artifactId)
          && Objects.equals(this.version, that.version);
    }

    @Override
    public int hashCode() {
      return Objects.hash(groupId, artifactId, version);
    }
  }
}
