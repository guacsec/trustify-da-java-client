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
package io.github.guacsec.trustifyda.providers.gradle.workspace;

import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.providers.JavaMavenProvider;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.WorkspaceUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Discovers Gradle multi-project build manifest paths using a custom init script. */
public final class GradleWorkspaceDiscovery {

  private static final Logger LOG =
      LoggersFactory.getLogger(GradleWorkspaceDiscovery.class.getName());

  private static final String GRADLE_INIT_SCRIPT =
      "allprojects {\n"
          + "    task daListProjects {\n"
          + "        doLast {\n"
          + "            println \"::DA_PROJECT::${project.path}::${project.projectDir}\"\n"
          + "        }\n"
          + "    }\n"
          + "}\n";

  private GradleWorkspaceDiscovery() {}

  public static List<Path> discoverSubprojects(Path workspaceDir, Set<String> ignorePatterns) {
    Path rootBuildKts = workspaceDir.resolve("build.gradle.kts");
    Path rootBuild = workspaceDir.resolve("build.gradle");

    List<Path> manifestPaths = new ArrayList<>();
    if (Files.isRegularFile(rootBuildKts)) {
      manifestPaths.add(rootBuildKts);
    } else if (Files.isRegularFile(rootBuild)) {
      manifestPaths.add(rootBuild);
    }

    String gradleBin = resolveGradleBinary(workspaceDir);
    Path initScriptPath = null;
    try {
      initScriptPath = Files.createTempFile("da-list-projects-", ".gradle");
      Files.writeString(initScriptPath, GRADLE_INIT_SCRIPT);

      Operations.ProcessExecOutput output =
          Operations.runProcessGetFullOutput(
              workspaceDir,
              new String[] {
                gradleBin,
                "-q",
                "--no-daemon",
                "--init-script",
                initScriptPath.toString(),
                "daListProjects"
              },
              null);

      if (output.getExitCode() != 0) {
        LOG.warning(
            "gradle daListProjects failed with exit code "
                + output.getExitCode()
                + ": "
                + output.getError());
        return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifestPaths, ignorePatterns);
      }

      for (var proj : parseGradleInitScriptOutput(output.getOutput())) {
        if (":".equals(proj.path())) {
          continue;
        }
        Path projDir = Path.of(proj.dir()).toAbsolutePath().normalize();
        Path buildKts = projDir.resolve("build.gradle.kts");
        Path buildGroovy = projDir.resolve("build.gradle");
        if (Files.isRegularFile(buildKts)) {
          manifestPaths.add(buildKts);
        } else if (Files.isRegularFile(buildGroovy)) {
          manifestPaths.add(buildGroovy);
        }
      }
    } catch (Exception e) {
      LOG.log(Level.WARNING, "Failed to discover Gradle subprojects", e);
      return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifestPaths, ignorePatterns);
    } finally {
      if (initScriptPath != null) {
        try {
          Files.deleteIfExists(initScriptPath);
        } catch (IOException ignored) {
        }
      }
    }

    return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifestPaths, ignorePatterns);
  }

  static String resolveGradleBinary(Path startDir) {
    if (Operations.getWrapperPreference("gradle")) {
      String wrapperName = Operations.isWindows() ? "gradlew.bat" : "gradlew";
      String wrapper =
          JavaMavenProvider.traverseForMvnw(
              wrapperName, startDir.resolve("build.gradle").toString(), null);
      if (wrapper != null) {
        return wrapper;
      }
    }
    return Operations.getCustomPathOrElse("gradle");
  }

  record GradleProject(String path, String dir) {}

  static List<GradleProject> parseGradleInitScriptOutput(String raw) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    String prefix = "::DA_PROJECT::";
    List<GradleProject> projects = new ArrayList<>();
    for (String line : raw.lines().toList()) {
      if (!line.startsWith(prefix)) {
        continue;
      }
      String remainder = line.substring(prefix.length());
      int lastSep = remainder.lastIndexOf("::");
      if (lastSep < 0) {
        continue;
      }
      String path = remainder.substring(0, lastSep);
      String dir = remainder.substring(lastSep + 2);
      if (!path.isEmpty() && !dir.isEmpty()) {
        projects.add(new GradleProject(path, dir));
      }
    }
    return projects;
  }
}
