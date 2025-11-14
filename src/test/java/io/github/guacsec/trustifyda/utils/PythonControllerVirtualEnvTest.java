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
import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.guacsec.trustifyda.ExhortTest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.junitpioneer.jupiter.SetSystemProperty;
import org.mockito.Mockito;

class PythonControllerVirtualEnvTest extends ExhortTest {

  private static PythonControllerVirtualEnv pythonControllerVirtualEnv;
  private static PythonControllerVirtualEnv spiedPythonControllerVirtualEnv;

  private final ObjectMapper om = new ObjectMapper();

  @BeforeAll
  static void setUp() {

    pythonControllerVirtualEnv = new PythonControllerVirtualEnv("python3");
    spiedPythonControllerVirtualEnv = Mockito.spy(pythonControllerVirtualEnv);
  }

  @Test
  @RestoreSystemProperties
  void test_Virtual_Environment_Install_Best_Efforts() throws JsonProcessingException {
    System.setProperty(PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS, "true");
    System.setProperty(PROP_MATCH_MANIFEST_VERSIONS, "false");
    String requirementsTxt =
        getFileFromString("requirements.txt", "flask==9.9.9\ndeprecated==15.15.99\n");
    List<Map<String, Object>> dependencies =
        spiedPythonControllerVirtualEnv.getDependencies(requirementsTxt, true);

    System.out.println(om.writerWithDefaultPrettyPrinter().writeValueAsString(dependencies));
  }

  @Test
  @RestoreSystemProperties
  @SetSystemProperty(key = PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS, value = "true")
  void test_Virtual_Environment_Install_Best_Efforts_Conflict_MMV_Should_Throw_Runtime_Exception() {
    String requirementsTxt =
        getFileFromString("requirements.txt", "flask==9.9.9\ndeprecated==15.15.99\n");
    RuntimeException runtimeException =
        assertThrows(
            RuntimeException.class,
            () -> spiedPythonControllerVirtualEnv.getDependencies(requirementsTxt, true));
    assertTrue(runtimeException.getMessage().contains("Conflicting settings"));
  }

  @Test
  void test_Virtual_Environment_Flow() throws IOException {
    //    Mockito
    String requirementsTxt = "Jinja2==3.0.3";
    Path requirementsFilePath = Path.of(Environment.get("user.dir"), "requirements.txt");
    Files.write(requirementsFilePath, requirementsTxt.getBytes());

    spiedPythonControllerVirtualEnv.getDependencies(requirementsFilePath.toString(), true);
    verify(spiedPythonControllerVirtualEnv).prepareEnvironment(anyString());
    verify(spiedPythonControllerVirtualEnv).installPackages(anyString());
    verify(spiedPythonControllerVirtualEnv).cleanEnvironment(anyBoolean());
    verify(spiedPythonControllerVirtualEnv).cleanEnvironment(anyBoolean());
    verify(spiedPythonControllerVirtualEnv).automaticallyInstallPackageOnEnvironment();
    verify(spiedPythonControllerVirtualEnv, never()).isRealEnv();
    verify(spiedPythonControllerVirtualEnv, times(2)).isVirtualEnv();
    Files.delete(requirementsFilePath);
  }

  @Test
  void isRealEnv() {
    assertFalse(spiedPythonControllerVirtualEnv.isRealEnv());
  }

  @Test
  void isVirtualEnv() {
    assertTrue(spiedPythonControllerVirtualEnv.isVirtualEnv());
  }
}
