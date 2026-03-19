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
package io.github.guacsec.trustifyda.license;

import io.github.guacsec.trustifyda.Provider;
import java.nio.file.Path;

public final class ProjectLicense {

  private ProjectLicense() {}

  /**
   * Resolve project license from manifest and from LICENSE file in manifest directory. Uses local
   * pattern matching for LICENSE file identification (synchronous).
   *
   * @param manifestPath path to manifest
   * @return project license info with fromManifest, fromFile, and mismatch fields
   */
  public static ProjectLicenseInfo getProjectLicense(Provider provider, Path manifestPath) {
    String fromManifest = provider.readLicenseFromManifest();
    String fromFile = LicenseUtils.readLicenseFile(manifestPath);
    if (fromManifest == null || fromFile == null) {
      return new ProjectLicenseInfo(fromManifest, fromFile, false);
    }
    boolean mismatch =
        !LicenseUtils.normalizeSpdx(fromManifest).equals(LicenseUtils.normalizeSpdx(fromFile));
    return new ProjectLicenseInfo(fromManifest, fromFile, mismatch);
  }

  public record ProjectLicenseInfo(String fromManifest, String fromFile, boolean mismatch) {}
}
