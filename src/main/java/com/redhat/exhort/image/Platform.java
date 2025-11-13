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
package com.redhat.exhort.image;

import java.util.Objects;
import java.util.Set;

public class Platform {

  // $GOOS and $GOARCH
  // https://github.com/docker-library/bashbrew/blob/v0.1.2/architecture/oci-platform.go#L14-L27
  private static final Set<Platform> SUPPORTED_PLATFORMS =
      Set.of(
          new Platform().os("linux").arch("amd64"),
          new Platform().os("linux").arch("arm").variant("v5"),
          new Platform().os("linux").arch("arm").variant("v6"),
          new Platform().os("linux").arch("arm").variant("v7"),
          new Platform().os("linux").arch("arm64").variant("v8"),
          new Platform().os("linux").arch("386"),
          new Platform().os("linux").arch("mips64le"),
          new Platform().os("linux").arch("ppc64le"),
          new Platform().os("linux").arch("riscv64"),
          new Platform().os("linux").arch("s390x"),
          new Platform().os("windows").arch("arm64"));

  public static final Platform EMPTY_PLATFORM = new Platform();

  private String os;
  private String architecture;
  private String variant;

  private Platform() {}

  public Platform(String platform) {
    if (platform == null) {
      throw new IllegalArgumentException("Invalid platform: null");
    }

    String[] parts = platform.split("/");
    if (parts.length == 1) {
      this.os = "linux";
      this.architecture = parts[0];
    } else if (parts.length == 2) {
      this.os = parts[0];
      this.architecture = parts[1];
      this.variant = getVariant(this.os, this.architecture);
    } else if (parts.length == 3) {
      this.os = parts[0];
      this.architecture = parts[1];
      this.variant = parts[2];
    } else {
      throw new IllegalArgumentException(String.format("Invalid platform: %s", platform));
    }

    if (!SUPPORTED_PLATFORMS.contains(this)) {
      throw new IllegalArgumentException(
          String.format("Image platform is not supported: %s", platform));
    }
  }

  public Platform(String os, String arch, String variant) {
    if (arch == null) {
      throw new IllegalArgumentException("Invalid platform arch: null");
    }
    this.architecture = arch;

    if (os == null) {
      this.os = "linux";
    } else {
      this.os = os;
    }

    if (variant != null) {
      this.variant = variant;
    } else {
      this.variant = getVariant(this.os, this.architecture);
    }

    if (!SUPPORTED_PLATFORMS.contains(this)) {
      throw new IllegalArgumentException(
          String.format("Image platform is not supported: %s/%s/%s", os, arch, variant));
    }
  }

  static String getVariant(String os, String arch) {
    if ("linux".equals(os) && "arm64".equals(arch)) { // in case variant "v8" is not specified
      return "v8";
    }
    return null;
  }

  public static boolean isVariantRequired(String os, String arch) {
    return "linux".equals(os) && "arm".equals(arch);
  }

  private Platform os(String os) {
    this.os = os;
    return this;
  }

  private Platform arch(String arch) {
    this.architecture = arch;
    return this;
  }

  private Platform variant(String variant) {
    this.variant = variant;
    return this;
  }

  public String getOs() {
    return os;
  }

  public String getArchitecture() {
    return architecture;
  }

  public String getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Platform platform = (Platform) o;
    return Objects.equals(os, platform.os)
        && Objects.equals(architecture, platform.architecture)
        && Objects.equals(variant, platform.variant);
  }

  @Override
  public int hashCode() {
    return Objects.hash(os, architecture, variant);
  }

  @Override
  public String toString() {
    if (this.variant == null) {
      return String.format("%s/%s", this.os, this.architecture);
    } else {
      return String.format("%s/%s/%s", this.os, this.architecture, this.variant);
    }
  }
}
