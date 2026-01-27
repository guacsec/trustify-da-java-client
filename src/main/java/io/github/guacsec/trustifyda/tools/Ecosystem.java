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
package io.github.guacsec.trustifyda.tools;

import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.providers.CargoProvider;
import io.github.guacsec.trustifyda.providers.GoModulesProvider;
import io.github.guacsec.trustifyda.providers.GradleProvider;
import io.github.guacsec.trustifyda.providers.JavaMavenProvider;
import io.github.guacsec.trustifyda.providers.JavaScriptProviderFactory;
import io.github.guacsec.trustifyda.providers.PythonPipProvider;
import java.nio.file.Path;

/** Utility class used for instantiating providers. * */
public final class Ecosystem {

  public enum Type {
    MAVEN("maven"),
    NPM("npm"),
    PNPM("pnpm"),
    YARN("yarn"),
    GOLANG("golang"),
    PYTHON("pypi"),
    GRADLE("gradle"),
    CARGO("cargo");

    final String type;

    public String getType() {
      return type;
    }

    public String getExecutableShortName() {
      return switch (this) {
        case MAVEN -> "mvn";
        case NPM -> "npm";
        case PNPM -> "pnpm";
        case YARN -> "yarn";
        case GOLANG -> "go";
        case PYTHON -> "python";
        case GRADLE -> "gradle";
        case CARGO -> "cargo";
      };
    }

    Type(String type) {
      this.type = type;
    }
  }

  private Ecosystem() {
    // constructor not required for a utility class
  }

  /**
   * Utility function for instantiating {@link Provider} implementations.
   *
   * @param manifestPath the manifest Path
   * @return a {@link Provider} suited for this manifest type
   */
  public static Provider getProvider(final Path manifestPath) {
    var provider = resolveProvider(manifestPath);
    provider.validateLockFile(manifestPath.getParent());
    return provider;
  }

  private static Provider resolveProvider(final Path manifestPath) {
    var manifestFile = manifestPath.getFileName().toString();
    return switch (manifestFile) {
      case "pom.xml" -> new JavaMavenProvider(manifestPath);
      case "package.json" -> JavaScriptProviderFactory.create(manifestPath);
      case "go.mod" -> new GoModulesProvider(manifestPath);
      case "requirements.txt" -> new PythonPipProvider(manifestPath);
      case "build.gradle", "build.gradle.kts" -> new GradleProvider(manifestPath);
      case "Cargo.toml" -> new CargoProvider(manifestPath);
      default ->
          throw new IllegalStateException(String.format("Unknown manifest file %s", manifestFile));
    };
  }
}
