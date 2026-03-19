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
class JavaMavenProviderLicenseTest extends ExhortTest {

  private JavaMavenProvider createProvider(String testFolder) {
    Path pomPath = resolveFile("tst_manifests/maven/license/" + testFolder + "/pom.xml");
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString()))
          .thenReturn("mvn");
      return new JavaMavenProvider(pomPath);
    }
  }

  @Test
  void readLicenseFromManifest_returns_license_from_pom() {
    var provider = createProvider("pom_with_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isEqualTo("Apache-2.0");
  }

  @Test
  void readLicenseFromManifest_returns_first_license_when_multiple() {
    var provider = createProvider("pom_with_multiple_licenses");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isEqualTo("MIT");
  }

  @Test
  void readLicenseFromManifest_returns_null_when_no_licenses_section() {
    var provider = createProvider("pom_without_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isNull();
  }

  @Test
  void readLicenseFromManifest_returns_null_when_license_name_is_blank() {
    var provider = createProvider("pom_with_empty_license");
    String license = provider.readLicenseFromManifest();
    assertThat(license).isNull();
  }
}
