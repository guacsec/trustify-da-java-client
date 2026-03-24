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

import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.utils.PythonControllerBase;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public final class PythonPipProvider extends PythonProvider {

  public PythonPipProvider(Path manifest) {
    super(manifest);
  }

  @Override
  protected Path getRequirementsPath() {
    return manifest;
  }

  @Override
  protected void cleanupRequirementsPath(Path requirementsPath) {
    // No cleanup needed — the manifest is the requirements file itself.
  }

  @Override
  protected Set<PackageURL> getIgnoredDependencies(String manifestContent) {
    String[] lines = manifestContent.split(System.lineSeparator());
    return Arrays.stream(lines)
        .filter(this::containsIgnorePattern)
        .map(PythonPipProvider::extractDepFull)
        .map(this::splitToNameVersion)
        .map(dep -> toPurl(dep[0], dep[1]))
        .collect(Collectors.toSet());
  }

  private static String extractDepFull(String requirementLine) {
    return requirementLine.substring(0, requirementLine.indexOf("#")).trim();
  }

  private String[] splitToNameVersion(String nameVersion) {
    String[] result;
    if (nameVersion.matches(
        "[a-zA-Z0-9-_()]+={2}[0-9]{1,4}[.][0-9]{1,4}(([.][0-9]{1,4})|([.][a-zA-Z0-9]+)|([a-zA-Z0-9]+)|([.][a-zA-Z0-9]+[.][a-z-A-Z0-9]+))?")) {
      result = nameVersion.split("==");
    } else {
      String dependencyName = PythonControllerBase.getDependencyName(nameVersion);
      result = new String[] {dependencyName, "*"};
    }
    return result;
  }
}
