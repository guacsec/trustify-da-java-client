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
import io.github.guacsec.trustifyda.sbom.Sbom;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.tools.Operations;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Concrete implementation of the {@link JavaScriptProvider} used for converting dependency trees
 * for yarn projects (package.json) into a SBOM content for Stack analysis or Component analysis.
 *
 * <p>Depending on the Yarn version used a different {@link YarnProcessor} will be used
 */
public final class JavaScriptYarnProvider extends JavaScriptProvider {

  public static final String LOCK_FILE = "yarn.lock";
  public static final String CMD_NAME = Operations.isWindows() ? "yarn.cmd" : "yarn";

  private static final Pattern versionPattern = Pattern.compile("^([0-9]+)\\.");

  private final YarnProcessor processor;

  public JavaScriptYarnProvider(Path manifest) {
    super(manifest, Ecosystem.Type.YARN, CMD_NAME);
    this.processor = resolveVersion(manifest);
  }

  @Override
  protected String lockFileName() {
    return LOCK_FILE;
  }

  @Override
  protected String[] updateLockFileCmd(Path manifestDir) {
    return processor.installCmd(manifestDir);
  }

  @Override
  protected String[] listDepsCmd(boolean includeTransitive, Path manifestDir) {
    return processor.listDepsCmd(includeTransitive, manifestDir);
  }

  @Override
  protected String parseDepTreeOutput(String output) {
    return processor.parseDepTreeOutput(output);
  }

  @Override
  protected void addDependenciesToSbom(Sbom sbom, JsonNode depTree) {
    processor.addDependenciesToSbom(sbom, depTree);
  }

  @Override
  protected Map<String, PackageURL> getRootDependencies(JsonNode depTree) {
    return processor.getRootDependencies(depTree);
  }

  private YarnProcessor resolveVersion(Path manifestPath) {
    var cmd = Operations.getCustomPathOrElse(CMD_NAME);
    var output =
        Operations.runProcessGetOutput(
            manifestPath.getParent(), new String[] {cmd, "-v"}, getExecEnvAsArgs());
    var matcher = versionPattern.matcher(output);
    if (matcher.find()) {
      var majorVersion = Integer.parseInt(matcher.group(1));
      if (majorVersion == 1) {
        return new YarnClassicProcessor(packageManager(), manifest);
      }
      return new YarnBerryProcessor(packageManager(), manifest);
    }
    throw new IllegalStateException("Unable to resolve current Yarn version: " + output);
  }
}
