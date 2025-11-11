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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import com.redhat.exhort.tools.Operations;
import com.redhat.exhort.utils.Environment;
import java.io.File;
import java.nio.file.Path;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.ClearSystemProperty;
import org.junitpioneer.jupiter.SetSystemProperty;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class Javascript_Envs_Test {

  private static final Path MANIFEST_PATH =
      Path.of("src/test/resources/tst_manifests/npm/empty/package.json");

  @Test
  @SetSystemProperty(key = "NODE_HOME", value = "test-node-home")
  @SetSystemProperty(key = "PATH", value = "test-path")
  void test_javascript_get_envs() {
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class);
        MockedStatic<Environment> mockEnv =
            Mockito.mockStatic(Environment.class, Mockito.CALLS_REAL_METHODS)) {
      mockEnv.when(() -> Environment.get("PATH")).thenReturn("test-path");
      // Configure the mock to return "npm" when getExecutable is called
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString(), anyMap()))
          .thenReturn("npm");
      var envs = new JavaScriptNpmProvider(MANIFEST_PATH).getExecEnv();
      assertEquals(
          Collections.singletonMap("PATH", "test-path" + File.pathSeparator + "test-node-home"),
          envs);
    }
  }

  @Test
  @SetSystemProperty(key = "NODE_HOME", value = "test-node-home")
  void test_javascript_get_envs_no_path() {
    try (MockedStatic<Environment> mockEnv =
            mockStatic(Environment.class, Mockito.CALLS_REAL_METHODS);
        MockedStatic<Operations> mockOps = mockStatic(Operations.class)) {
      mockEnv.when(() -> Environment.get("PATH")).thenReturn(null);
      mockOps
          .when(() -> Operations.getExecutable(anyString(), anyString(), anyMap()))
          .thenReturn("npm");
      var envs = new JavaScriptNpmProvider(MANIFEST_PATH).getExecEnv();
      assertEquals(Collections.singletonMap("PATH", "test-node-home"), envs);
    }
  }

  @Test
  @SetSystemProperty(key = "NODE_HOME", value = "")
  @SetSystemProperty(key = "PATH", value = "test-path")
  void test_javascript_get_envs_empty_java_home() {
    var envs = new JavaScriptNpmProvider(MANIFEST_PATH).getExecEnv();
    assertNull(envs);
  }

  @Test
  @ClearSystemProperty(key = "NODE_HOME")
  @SetSystemProperty(key = "PATH", value = "test-path")
  void test_javascript_get_envs_no_java_home() {
    var envs = new JavaScriptNpmProvider(MANIFEST_PATH).getExecEnv();
    assertNull(envs);
  }
}
