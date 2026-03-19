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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import io.github.guacsec.trustifyda.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests LICENSE file fallback for providers without manifest license support. Mirrors the
 * JavaScript client's test/providers/license_fallback.test.js
 */
@ExtendWith(MockitoExtension.class)
class LicenseFallbackTest {

  @Test
  void gradle_provider_should_read_license_file_when_present(@TempDir Path tempDir)
      throws IOException {
    Files.writeString(tempDir.resolve("build.gradle"), "plugins { id 'java' }");
    Files.writeString(tempDir.resolve("LICENSE"), "Apache License, Version 2.0");

    try (MockedStatic<Operations> mock = mockStatic(Operations.class)) {
      mock.when(() -> Operations.getExecutable(anyString(), anyString())).thenReturn("gradle");
      var provider = new GradleProvider(tempDir.resolve("build.gradle"));
      assertThat(provider.readLicenseFromManifest()).isEqualTo("Apache-2.0");
    }
  }

  @Test
  void golang_provider_should_read_license_file_when_present(@TempDir Path tempDir)
      throws IOException {
    Files.writeString(tempDir.resolve("go.mod"), "module example.com/test");
    Files.writeString(tempDir.resolve("LICENSE"), "MIT License\n\nPermission is hereby granted");

    try (MockedStatic<Operations> mock = mockStatic(Operations.class)) {
      mock.when(() -> Operations.getExecutable(anyString(), anyString())).thenReturn("go");
      var provider = new GoModulesProvider(tempDir.resolve("go.mod"));
      assertThat(provider.readLicenseFromManifest()).isEqualTo("MIT");
    }
  }

  @Test
  void python_provider_should_read_license_file_when_present(@TempDir Path tempDir)
      throws IOException {
    Files.writeString(tempDir.resolve("requirements.txt"), "requests==2.28.0");
    Files.writeString(tempDir.resolve("LICENSE"), "BSD 3-Clause License");

    var provider = new PythonPipProvider(tempDir.resolve("requirements.txt"));
    assertThat(provider.readLicenseFromManifest()).isEqualTo("BSD-3-Clause");
  }

  @Test
  void providers_should_return_null_when_no_license_file_exists(@TempDir Path tempDir)
      throws IOException {
    Files.writeString(tempDir.resolve("go.mod"), "module example.com/test");

    try (MockedStatic<Operations> mock = mockStatic(Operations.class)) {
      mock.when(() -> Operations.getExecutable(anyString(), anyString())).thenReturn("go");
      var provider = new GoModulesProvider(tempDir.resolve("go.mod"));
      assertThat(provider.readLicenseFromManifest()).isNull();
    }
  }
}
