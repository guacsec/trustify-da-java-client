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

import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.tools.Operations;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CargoProviderLicenseTest extends ExhortTest {

  private CargoProvider createProvider(String testFolder) {
    Path cargoTomlPath = resolveFile("tst_manifests/cargo/license/" + testFolder + "/Cargo.toml");
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString()))
          .thenReturn("cargo");
      return new CargoProvider(cargoTomlPath);
    }
  }

  @Test
  void readLicenseFromManifest_returns_license_from_cargo_toml() {
    var provider = createProvider("cargo_with_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isEqualTo("MIT");
  }

  @Test
  void readLicenseFromManifest_returns_null_when_no_license() {
    var provider = createProvider("cargo_without_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isNull();
  }
}
