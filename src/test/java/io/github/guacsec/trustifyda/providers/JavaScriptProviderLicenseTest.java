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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Operations;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class JavaScriptProviderLicenseTest extends ExhortTest {

  private JavaScriptProvider createProvider(String testFolder) {
    Path packageJsonPath = resolveFile("tst_manifests/npm/license/" + testFolder + "/package.json");
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString(), any()))
          .thenReturn("npm");
      return JavaScriptProviderFactory.create(packageJsonPath);
    }
  }

  @Test
  void readLicenseFromManifest_returns_license_field() {
    var provider = createProvider("package_with_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isEqualTo("MIT");
  }

  @Test
  void readLicenseFromManifest_returns_first_from_legacy_licenses_array() {
    var provider = createProvider("package_with_legacy_licenses");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isEqualTo("Apache-2.0");
  }

  @Test
  void readLicenseFromManifest_returns_null_when_no_license() {
    var provider = createProvider("package_without_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isNull();
  }
}
