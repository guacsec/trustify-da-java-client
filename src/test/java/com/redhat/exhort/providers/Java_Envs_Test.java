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

import com.redhat.exhort.utils.Environment;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class Java_Envs_Test {

  @Test
  @SetSystemProperty(key = "JAVA_HOME", value = "test-java-home")
  void test_java_get_envs() {
    try (MockedStatic<Environment> mockEnv =
        Mockito.mockStatic(Environment.class, Mockito.CALLS_REAL_METHODS)) {
      mockEnv.when(() -> Environment.get("JAVA_HOME")).thenReturn("test-java-home");
      var envs = new JavaMavenProvider(null).getMvnExecEnvs();
      assertEquals(Collections.singletonMap("JAVA_HOME", "test-java-home"), envs);
    }
  }

  @Test
  @SetSystemProperty(key = "JAVA_HOME", value = "")
  void test_java_get_envs_empty_java_home() {
    try (MockedStatic<Environment> mockEnv =
        Mockito.mockStatic(Environment.class, Mockito.CALLS_REAL_METHODS)) {
      mockEnv.when(() -> Environment.get("JAVA_HOME")).thenReturn(null);
      var envs = new JavaMavenProvider(null).getMvnExecEnvs();
      assertNull(envs);
    }
  }

  @Test
  void test_java_get_envs_no_java_home() {
    try (MockedStatic<Environment> mockEnv =
        Mockito.mockStatic(Environment.class, Mockito.CALLS_REAL_METHODS)) {
      mockEnv.when(() -> Environment.get("JAVA_HOME")).thenReturn(null);
      var envs = new JavaMavenProvider(null).getMvnExecEnvs();
      assertNull(envs);
    }
  }
}
