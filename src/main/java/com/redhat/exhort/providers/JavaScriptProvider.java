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
package com.redhat.exhort.providers;

import static com.redhat.exhort.impl.ExhortApi.debugLoggingIsNeeded;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.redhat.exhort.Api;
import com.redhat.exhort.Provider;
import com.redhat.exhort.logging.LoggersFactory;
import com.redhat.exhort.providers.javascript.model.Manifest;
import com.redhat.exhort.sbom.Sbom;
import com.redhat.exhort.sbom.SbomFactory;
import com.redhat.exhort.tools.Ecosystem;
import com.redhat.exhort.tools.Operations;
import com.redhat.exhort.utils.Environment;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.logging.Logger;

/**
 * Abstract implementation of the {@link Provider} used for converting dependency trees for
 * Javascript/Typescript projects (package.json) into a SBOM content for Stack analysis or Component
 * analysis. See concrete implementations for more details.
 */
public abstract class JavaScriptProvider extends Provider {

  public static final String ENV_NODE_HOME = "NODE_HOME";
  private static final String PROP_PATH = "PATH";

  private static final Logger log = LoggersFactory.getLogger(JavaScriptProvider.class.getName());

  protected final String cmd;
  protected final Manifest manifest;

  public JavaScriptProvider(Path manifest, Ecosystem.Type ecosystem, String cmd) {
    super(ecosystem, manifest);
    this.cmd = Operations.getExecutable(cmd, "-v", getExecEnv());
    try {
      this.manifest = new Manifest(manifest);
    } catch (IOException e) {
      throw new RuntimeException("Unable to process package.json file", e);
    }
  }

  protected final String packageManager() {
    return cmd;
  }

  protected abstract String lockFileName();

  protected String pathEnv() {
    return ENV_NODE_HOME;
  }

  protected abstract String[] updateLockFileCmd(Path manifestDir);

  protected abstract String[] listDepsCmd(boolean includeTransitive, Path manifestDir);

  @Override
  public Content provideStack() throws IOException {
    Sbom sbom = getDependencySbom();
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideComponent() throws IOException {
    return new Content(
        getDirectDependencySbom().getAsJsonString().getBytes(StandardCharsets.UTF_8),
        Api.CYCLONEDX_MEDIA_TYPE);
  }

  public static PackageURL toPurl(String name, String version) {
    try {
      String[] parts = name.split("/");
      if (parts.length == 2) {
        return new PackageURL(
            Ecosystem.Type.NPM.getType(), parts[0], parts[1], version, null, null);
      }
      return new PackageURL(Ecosystem.Type.NPM.getType(), null, parts[0], version, null, null);
    } catch (MalformedPackageURLException e) {
      throw new IllegalArgumentException("Unable to parse PackageURL", e);
    }
  }

  public static PackageURL toPurl(String name) {
    try {
      return new PackageURL(String.format("pkg:%s/%s", Ecosystem.Type.NPM.getType(), name));
    } catch (MalformedPackageURLException e) {
      throw new IllegalArgumentException("Unable to parse PackageURL", e);
    }
  }

  private void addDependenciesOf(Sbom sbom, PackageURL from, JsonNode node) {
    var dependencies = node.get("dependencies");
    if (dependencies == null) {
      return;
    }
    Iterator<Entry<String, JsonNode>> fields = dependencies.fields();
    while (fields.hasNext()) {
      Entry<String, JsonNode> e = fields.next();
      String name = e.getKey();
      JsonNode versionNode = e.getValue().get("version");
      if (versionNode == null) {
        continue; // ignore optional dependencies
      }
      String version = versionNode.asText();
      PackageURL purl = toPurl(name, version);
      sbom.addDependency(from, purl, null);
      addDependenciesOf(sbom, purl, e.getValue());
    }
  }

  protected final String[] getExecEnvAsArgs() {
    String[] envs = null;
    if (getExecEnv() != null) {
      envs =
          getExecEnv().entrySet().stream()
              .map(e -> e.getKey() + "=" + e.getValue())
              .toArray(String[]::new);
    }
    return envs;
  }

  private Sbom getDependencySbom() throws IOException {
    var depTree = buildDependencyTree(true);
    var sbom = SbomFactory.newInstance();
    sbom.addRoot(manifest.root);
    addDependenciesToSbom(sbom, depTree);
    sbom.filterIgnoredDeps(manifest.ignored);
    return sbom;
  }

  protected void addDependenciesToSbom(Sbom sbom, JsonNode depTree) {
    var deps = depTree.get("dependencies");
    if (deps == null) {
      return;
    }
    deps.fields()
        .forEachRemaining(
            e -> {
              var version = e.getValue().get("version").asText();
              var target = toPurl(e.getKey(), version);
              sbom.addDependency(manifest.root, target, null);
              addDependenciesOf(sbom, target, e.getValue());
            });
  }

  private Sbom getDirectDependencySbom() throws IOException {
    var depTree = buildDependencyTree(false);
    var sbom = SbomFactory.newInstance();
    sbom.addRoot(manifest.root);
    // include only production dependencies for component analysis
    getRootDependencies(depTree).entrySet().stream()
        .filter(e -> manifest.dependencies.contains(e.getKey()))
        .map(Entry::getValue)
        .forEach(p -> sbom.addDependency(manifest.root, p, null));
    sbom.filterIgnoredDeps(manifest.ignored);
    return sbom;
  }

  // Returns the dependencies a base level of the dependency tree in a name -> purl format.
  // axios -> pkg:npm/axios@0.19.2
  protected Map<String, PackageURL> getRootDependencies(JsonNode depTree) {
    Map<String, PackageURL> direct = new TreeMap<>();
    depTree
        .get("dependencies")
        .fields()
        .forEachRemaining(
            e -> {
              String name = e.getKey();
              JsonNode versionNode = e.getValue().get("version");
              if (versionNode != null) {
                String version = versionNode.asText();
                PackageURL purl = toPurl(name, version);
                direct.put(name, purl);
              }
            });
    return direct;
  }

  protected JsonNode buildDependencyTree(boolean includeTransitive) throws JsonProcessingException {
    // clean command used to clean build target
    Path manifestDir;
    try {
      // MacOS requires resolving to the CanonicalPath to avoid problems with /var
      // being a symlink
      // of /private/var
      manifestDir = Path.of(manifest.path.getParent().toFile().getCanonicalPath());
    } catch (IOException e) {
      throw new RuntimeException(
          String.format(
              "Unable to resolve manifest directory %s, got %s",
              manifest.path.getParent(), e.getMessage()));
    }
    var createPackageLock = updateLockFileCmd(manifestDir);
    // execute the clean command
    Operations.runProcess(manifestDir, createPackageLock, getExecEnv());
    String[] allDeps = listDepsCmd(includeTransitive, manifestDir);
    // execute the clean command
    String output = Operations.runProcessGetOutput(manifestDir, allDeps, getExecEnvAsArgs());
    if (debugLoggingIsNeeded()) {
      log.info(
          String.format("Listed Install Packages in Json : %s %s", System.lineSeparator(), output));
    }
    output = parseDepTreeOutput(output);
    return objectMapper.readTree(output);
  }

  protected String parseDepTreeOutput(String output) {
    // Do nothing by default
    return output;
  }

  protected List<String> getIgnoredDeps(JsonNode manifest) {
    var ignored = new ArrayList<String>();
    var ignoredNode = manifest.withArray("exhortignore");
    if (ignoredNode == null) {
      return ignored;
    }
    for (JsonNode n : ignoredNode) {
      ignored.add(n.asText());
    }
    return ignored;
  }

  protected Map<String, String> getExecEnv() {
    String pathEnv = Environment.get(pathEnv());
    if (pathEnv != null && !pathEnv.isBlank()) {
      String path = Environment.get(PROP_PATH);
      if (path != null) {
        return Collections.singletonMap(PROP_PATH, path + File.pathSeparator + pathEnv);
      } else {
        return Collections.singletonMap(PROP_PATH, pathEnv);
      }
    }
    return null;
  }

  @Override
  public void validateLockFile(Path lockFileDir) {
    if (!Files.isRegularFile(lockFileDir.resolve(lockFileName()))) {
      throw new IllegalStateException(
          String.format(
              "Lock file does not exist or is not supported. Execute '%s install' to generate it.",
              packageManager()));
    }
  }
}
