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
package io.github.guacsec.trustifyda.utils;

import static io.github.guacsec.trustifyda.Provider.PROP_MATCH_MANIFEST_VERSIONS;
import static io.github.guacsec.trustifyda.utils.PythonControllerBaseTest.matchCommandPipFreeze;
import static io.github.guacsec.trustifyda.utils.PythonControllerBaseTest.matchCommandPipShow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;

import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Operations;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.junitpioneer.jupiter.SetSystemProperty;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class PythonControllerRealEnvTest extends ExhortTest {

  private static PythonControllerRealEnv pythonControllerRealEnv;
  private final String PIP_FREEZE_LINES_CYCLIC =
      getStringFromFile("msc/python/pip_freeze_lines_cyclic.txt");
  private final String PIP_SHOW_LINES_CYCLIC =
      getStringFromFile("msc/python/pip_show_lines_cyclic.txt");

  @BeforeEach
  void setUp() {
    pythonControllerRealEnv = new PythonControllerRealEnv("python3", "pip3");
  }

  @AfterEach
  void tearDown() {}

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void get_Dependencies_With_Match_Manifest_Versions(boolean MatchManifestVersionsEnabled) {
    Set<String> expectedSetOfPackages =
        Set.of(
            "click",
            "flask",
            "importlib-metadata",
            "zipp",
            "itsdangerous",
            "jinja2",
            "MarkupSafe",
            "Werkzeug",
            "dataclasses",
            "typing-extensions");
    MockedStatic<Operations> operationsMockedStatic = Mockito.mockStatic(Operations.class);
    String requirementsPath = getFileFromString("requirements.txt", "Flask==2.0.3\nclick==8.0.5\n");
    String pipFreeze =
        "click==8.0.4\n"
            + "flask==2.0.3\n"
            + "importlib-metadata==4.8.3\n"
            + "zipp==3.6.0\n"
            + "itsdangerous==2.0.1\n"
            + "jinja2==3.0.3\n"
            + "MarkupSafe==2.0.1\n"
            + "Werkzeug==2.0.3\n"
            + "dataclasses==0.8\n"
            + "typing_extensions==4.1.1\n";
    String pipShowResults =
        "Name: click\n"
            + "Version: 8.0.4\n"
            + "Summary: Composable command line interface toolkit\n"
            + "Home-page: https://palletsprojects.com/p/click/\n"
            + "Author: Armin Ronacher\n"
            + "Author-email: armin.ronacher@active-4.com\n"
            + "License: BSD-3-Clause\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: importlib-metadata\n"
            + "Required-by: Flask, uvicorn\n"
            + "---\n"
            + "Name: Flask\n"
            + "Version: 2.0.3\n"
            + "Summary: A simple framework for building complex web applications.\n"
            + "Home-page: https://palletsprojects.com/p/flask\n"
            + "Author: Armin Ronacher\n"
            + "Author-email: armin.ronacher@active-4.com\n"
            + "License: BSD-3-Clause\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: click, itsdangerous, Jinja2, Werkzeug\n"
            + "Required-by: \n"
            + "---\n"
            + "Name: importlib-metadata\n"
            + "Version: 4.8.3\n"
            + "Summary: Read metadata from Python packages\n"
            + "Home-page: https://github.com/python/importlib_metadata\n"
            + "Author: Jason R. Coombs\n"
            + "Author-email: jaraco@jaraco.com\n"
            + "License: UNKNOWN\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: typing-extensions, zipp\n"
            + "Required-by: click, cyclonedx-bom, cyclonedx-python-lib\n"
            + "---\n"
            + "Name: zipp\n"
            + "Version: 3.6.0\n"
            + "Summary: Backport of pathlib-compatible object wrapper for zip files\n"
            + "Home-page: https://github.com/jaraco/zipp\n"
            + "Author: Jason R. Coombs\n"
            + "Author-email: jaraco@jaraco.com\n"
            + "License: UNKNOWN\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: \n"
            + "Required-by: importlib-metadata\n"
            + "---\n"
            + "Name: itsdangerous\n"
            + "Version: 2.0.1\n"
            + "Summary: Safely pass data to untrusted environments and back.\n"
            + "Home-page: https://palletsprojects.com/p/itsdangerous/\n"
            + "Author: Armin Ronacher\n"
            + "Author-email: armin.ronacher@active-4.com\n"
            + "License: BSD-3-Clause\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: \n"
            + "Required-by: Flask\n"
            + "---\n"
            + "Name: Jinja2\n"
            + "Version: 3.0.3\n"
            + "Summary: A very fast and expressive template engine.\n"
            + "Home-page: https://palletsprojects.com/p/jinja/\n"
            + "Author: Armin Ronacher\n"
            + "Author-email: armin.ronacher@active-4.com\n"
            + "License: BSD-3-Clause\n"
            + "Location: /home/zgrinber/.local/lib/python3.6/site-packages\n"
            + "Requires: MarkupSafe\n"
            + "Required-by: ansible-core, Flask\n"
            + "---\n"
            + "Name: MarkupSafe\n"
            + "Version: 2.0.1\n"
            + "Summary: Safely add untrusted strings to HTML/XML markup.\n"
            + "Home-page: https://palletsprojects.com/p/markupsafe/\n"
            + "Author: Armin Ronacher\n"
            + "Author-email: armin.ronacher@active-4.com\n"
            + "License: BSD-3-Clause\n"
            + "Location: /home/zgrinber/.local/lib/python3.6/site-packages\n"
            + "Requires: \n"
            + "Required-by: Jinja2, Mako\n"
            + "---\n"
            + "Name: Werkzeug\n"
            + "Version: 2.0.3\n"
            + "Summary: The comprehensive WSGI web application library.\n"
            + "Home-page: https://palletsprojects.com/p/werkzeug/\n"
            + "Author: Armin Ronacher\n"
            + "Author-email: armin.ronacher@active-4.com\n"
            + "License: BSD-3-Clause\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: dataclasses\n"
            + "Required-by: Flask\n"
            + "---\n"
            + "Name: dataclasses\n"
            + "Version: 0.8\n"
            + "Summary: A backport of the dataclasses module for Python 3.6\n"
            + "Home-page: https://github.com/ericvsmith/dataclasses\n"
            + "Author: Eric V. Smith\n"
            + "Author-email: eric@python.org\n"
            + "License: Apache\n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: \n"
            + "Required-by: anyio, h11, pydantic, Werkzeug\n"
            + "---\n"
            + "Name: typing_extensions\n"
            + "Version: 4.1.1\n"
            + "Summary: Backported and Experimental Type Hints for Python 3.6+\n"
            + "Home-page: \n"
            + "Author: \n"
            + "Author-email: \"Guido van Rossum, Jukka Lehtosalo, Łukasz Langa, Michael Lee\""
            + " <levkivskyi@gmail.com>\n"
            + "License: \n"
            + "Location: /usr/local/lib/python3.6/site-packages\n"
            + "Requires: \n"
            + "Required-by: anyio, asgiref, h11, immutables, importlib-metadata, pydantic,"
            + " starlette, uvicorn\n";

    operationsMockedStatic
        .when(() -> Operations.runProcessGetOutput(any(Path.class), argThat(matchCommandPipFreeze)))
        .thenReturn(pipFreeze);
    operationsMockedStatic
        .when(() -> Operations.runProcessGetOutput(any(Path.class), argThat(matchCommandPipShow)))
        .thenReturn(pipShowResults);
    if (!MatchManifestVersionsEnabled) {
      System.setProperty(PROP_MATCH_MANIFEST_VERSIONS, "false");
    }
    if (MatchManifestVersionsEnabled) {
      RuntimeException runtimeException =
          assertThrows(
              RuntimeException.class,
              () -> pythonControllerRealEnv.getDependencies(requirementsPath, true),
              "Expected getDependencies/2 to throw RuntimeException, due to version mismatch, but"
                  + " it didn't.");
      operationsMockedStatic.close();
      assertTrue(
          runtimeException
              .getMessage()
              .contains(
                  "Can't continue with analysis - versions mismatch for dependency name=click,"
                      + " manifest version=8.0.5, installed Version=8.0.4"));
    } else {

      List<Map<String, Object>> dependencies =
          pythonControllerRealEnv.getDependencies(requirementsPath, true);
      System.clearProperty(PROP_MATCH_MANIFEST_VERSIONS);
      // collect all packages returned from getDependencies into Set.
      System.out.println(dependencies);
      Set<String> actualSetOfPackages = new HashSet<>();
      dependencies.forEach(entry -> accumulateAllPackages(entry, actualSetOfPackages));

      // Check that all actual collected packages are exactly the ones that are expected
      Set<String> expectedSetOfPackagesLC =
          expectedSetOfPackages.stream()
              .map(packageName -> packageName.replace("_", "-"))
              .map(String::toLowerCase)
              .collect(Collectors.toSet());

      Set<String> actualSetOfPackagesLC =
          actualSetOfPackages.stream()
              .map(packageName -> packageName.replace("_", "-"))
              .map(String::toLowerCase)
              .collect(Collectors.toSet());
      assertTrue(actualSetOfPackagesLC.containsAll(expectedSetOfPackagesLC));
      assertTrue(expectedSetOfPackagesLC.containsAll(actualSetOfPackagesLC));
      operationsMockedStatic.close();
    }
  }

  private void accumulateAllPackages(Map<String, Object> entry, Set actualSetOfPackages) {
    actualSetOfPackages.add(entry.get("name"));
    if (entry.get("dependencies") != null) {
      ((List<Map<String, Object>>) entry.get("dependencies"))
          .stream().forEach(record -> accumulateAllPackages(record, actualSetOfPackages));
    }
  }

  @Test
  @RestoreSystemProperties
  @SetSystemProperty(key = PROP_MATCH_MANIFEST_VERSIONS, value = "false")
  void get_Dependencies_from_Cyclic_Tree() {
    MockedStatic<Operations> operationsMockedStatic = Mockito.mockStatic(Operations.class);

    operationsMockedStatic
        .when(() -> Operations.runProcessGetOutput(any(Path.class), argThat(matchCommandPipFreeze)))
        .thenReturn(PIP_FREEZE_LINES_CYCLIC);
    operationsMockedStatic
        .when(() -> Operations.runProcessGetOutput(any(Path.class), argThat(matchCommandPipShow)))
        .thenReturn(PIP_SHOW_LINES_CYCLIC);
    String requirementsTxt =
        getFileFromResource("requirements.txt", "msc/python/requirements-cyclic-test.txt");
    List<Map<String, Object>> dependencies =
        pythonControllerRealEnv.getDependencies(requirementsTxt, true);
    assertEquals(104, dependencies.size());

    operationsMockedStatic.close();
  }

  @Test
  void get_Dependency_Name_requirements() {
    assertEquals("something", PythonControllerRealEnv.getDependencyName("something==2.0.5"));
    assertEquals("something", PythonControllerRealEnv.getDependencyName("something == 2.0.5"));
    assertEquals("something", PythonControllerRealEnv.getDependencyName("something>=2.0.5"));
  }

  @Test
  void automaticallyInstallPackageOnEnvironment() {
    assertFalse(pythonControllerRealEnv.automaticallyInstallPackageOnEnvironment());
  }

  @Test
  void isRealEnv() {

    assertTrue(pythonControllerRealEnv.isRealEnv());
  }

  @Test
  void isVirtualEnv() {
    assertFalse(pythonControllerRealEnv.isVirtualEnv());
  }
}
