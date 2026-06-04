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

import static org.assertj.core.api.Assertions.assertThat;

import io.github.guacsec.trustifyda.api.v5.LicenseCategory;
import io.github.guacsec.trustifyda.license.LicenseUtils.Compatibility;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/** Tests for {@link LicenseUtils#getCompatibility} with UNKNOWN category handling. */
class License_Compatibility_Test {

  @Nested
  class Unknown_Dependency_Category {

    /** Known project + UNKNOWN dependency should be INCOMPATIBLE. */
    @ParameterizedTest
    @EnumSource(
        value = LicenseCategory.class,
        names = {"PERMISSIVE", "WEAK_COPYLEFT", "STRONG_COPYLEFT"})
    void known_project_and_unknown_dependency_returns_incompatible(
        LicenseCategory projectCategory) {
      // When
      Compatibility result =
          LicenseUtils.getCompatibility(projectCategory, LicenseCategory.UNKNOWN);

      // Then
      assertThat(result).isEqualTo(Compatibility.INCOMPATIBLE);
    }
  }

  @Nested
  class Unknown_Project_Category {

    /** UNKNOWN project category should always return UNKNOWN. */
    @ParameterizedTest
    @EnumSource(LicenseCategory.class)
    void unknown_project_returns_unknown(LicenseCategory dependencyCategory) {
      // When
      Compatibility result =
          LicenseUtils.getCompatibility(LicenseCategory.UNKNOWN, dependencyCategory);

      // Then
      assertThat(result).isEqualTo(Compatibility.UNKNOWN);
    }

    /** Null project category should return UNKNOWN. */
    @ParameterizedTest
    @EnumSource(LicenseCategory.class)
    void null_project_returns_unknown(LicenseCategory dependencyCategory) {
      // When
      Compatibility result = LicenseUtils.getCompatibility(null, dependencyCategory);

      // Then
      assertThat(result).isEqualTo(Compatibility.UNKNOWN);
    }
  }

  @Nested
  class Known_Categories {

    /** Existing compatibility logic for known categories remains unchanged. */
    @ParameterizedTest
    @MethodSource(
        "io.github.guacsec.trustifyda.license.License_Compatibility_Test#knownCategoryPairs")
    void known_categories_preserve_existing_behavior(
        LicenseCategory project, LicenseCategory dependency, Compatibility expected) {
      // When
      Compatibility result = LicenseUtils.getCompatibility(project, dependency);

      // Then
      assertThat(result).isEqualTo(expected);
    }
  }

  static Stream<Arguments> knownCategoryPairs() {
    return Stream.of(
        // Same restrictiveness → compatible
        Arguments.of(
            LicenseCategory.PERMISSIVE, LicenseCategory.PERMISSIVE, Compatibility.COMPATIBLE),
        Arguments.of(
            LicenseCategory.WEAK_COPYLEFT, LicenseCategory.WEAK_COPYLEFT, Compatibility.COMPATIBLE),
        Arguments.of(
            LicenseCategory.STRONG_COPYLEFT,
            LicenseCategory.STRONG_COPYLEFT,
            Compatibility.COMPATIBLE),
        // Less restrictive dependency → compatible
        Arguments.of(
            LicenseCategory.STRONG_COPYLEFT, LicenseCategory.PERMISSIVE, Compatibility.COMPATIBLE),
        Arguments.of(
            LicenseCategory.STRONG_COPYLEFT,
            LicenseCategory.WEAK_COPYLEFT,
            Compatibility.COMPATIBLE),
        Arguments.of(
            LicenseCategory.WEAK_COPYLEFT, LicenseCategory.PERMISSIVE, Compatibility.COMPATIBLE),
        // More restrictive dependency → incompatible
        Arguments.of(
            LicenseCategory.PERMISSIVE, LicenseCategory.WEAK_COPYLEFT, Compatibility.INCOMPATIBLE),
        Arguments.of(
            LicenseCategory.PERMISSIVE,
            LicenseCategory.STRONG_COPYLEFT,
            Compatibility.INCOMPATIBLE),
        Arguments.of(
            LicenseCategory.WEAK_COPYLEFT,
            LicenseCategory.STRONG_COPYLEFT,
            Compatibility.INCOMPATIBLE));
  }
}
