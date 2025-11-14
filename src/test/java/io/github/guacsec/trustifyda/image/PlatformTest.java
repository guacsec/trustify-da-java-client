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
package io.github.guacsec.trustifyda.image;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PlatformTest {

  static Stream<Arguments> PlatformSources() {
    return Stream.of(
        Arguments.of(Named.of("amd64", "amd64"), "linux", "amd64", null, "linux/amd64", false),
        Arguments.of(
            Named.of("linux/amd64", "linux/amd64"), "linux", "amd64", null, "linux/amd64", false),
        Arguments.of(
            Named.of("linux/arm/v5", "linux/arm/v5"), "linux", "arm", "v5", "linux/arm/v5", true),
        Arguments.of(
            Named.of("linux/arm/v6", "linux/arm/v6"), "linux", "arm", "v6", "linux/arm/v6", true),
        Arguments.of(
            Named.of("linux/arm/v7", "linux/arm/v7"), "linux", "arm", "v7", "linux/arm/v7", true),
        Arguments.of(
            Named.of("linux/arm64", "linux/arm64"),
            "linux",
            "arm64",
            "v8",
            "linux/arm64/v8",
            false),
        Arguments.of(
            Named.of("linux/arm64/v8", "linux/arm64/v8"),
            "linux",
            "arm64",
            "v8",
            "linux/arm64/v8",
            false),
        Arguments.of(Named.of("linux/386", "linux/386"), "linux", "386", null, "linux/386", false),
        Arguments.of(
            Named.of("linux/mips64le", "linux/mips64le"),
            "linux",
            "mips64le",
            null,
            "linux/mips64le",
            false),
        Arguments.of(
            Named.of("linux/ppc64le", "linux/ppc64le"),
            "linux",
            "ppc64le",
            null,
            "linux/ppc64le",
            false),
        Arguments.of(
            Named.of("linux/riscv64", "linux/riscv64"),
            "linux",
            "riscv64",
            null,
            "linux/riscv64",
            false),
        Arguments.of(
            Named.of("linux/s390x", "linux/s390x"), "linux", "s390x", null, "linux/s390x", false),
        Arguments.of(
            Named.of("windows/arm64", "windows/arm64"),
            "windows",
            "arm64",
            null,
            "windows/arm64",
            false));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("PlatformSources")
  void test_platform(
      String platform,
      String os,
      String arch,
      String variant,
      String platformStr,
      boolean variantRequired) {
    var p = new Platform(platform);

    assertEquals(os, p.getOs());
    assertEquals(arch, p.getArchitecture());
    assertEquals(variant, p.getVariant());
    assertEquals(platformStr, p.toString());
    assertEquals(variantRequired, Platform.isVariantRequired(p.getOs(), p.getArchitecture()));

    var pf = new Platform(os, arch, variant);
    assertEquals(p, pf);
    assertEquals(p.hashCode(), pf.hashCode());
  }

  @Test
  void test_platform_invalid() {
    var exception1 = assertThrows(IllegalArgumentException.class, () -> new Platform(null));
    assertEquals("Invalid platform: null", exception1.getMessage());

    var exception2 =
        assertThrows(IllegalArgumentException.class, () -> new Platform("linux/arm/v8/a"));
    assertEquals("Invalid platform: linux/arm/v8/a", exception2.getMessage());

    var exception3 = assertThrows(IllegalArgumentException.class, () -> new Platform("linux/abc"));
    assertEquals("Image platform is not supported: linux/abc", exception3.getMessage());

    var exception4 = assertThrows(IllegalArgumentException.class, () -> new Platform("", null, ""));
    assertEquals("Invalid platform arch: null", exception4.getMessage());

    var exception5 =
        assertThrows(IllegalArgumentException.class, () -> new Platform("linux", "arm", "v8"));
    assertEquals("Image platform is not supported: linux/arm/v8", exception5.getMessage());

    var exception6 =
        assertThrows(IllegalArgumentException.class, () -> new Platform(null, "arm", null));
    assertEquals("Image platform is not supported: null/arm/null", exception6.getMessage());
  }
}
