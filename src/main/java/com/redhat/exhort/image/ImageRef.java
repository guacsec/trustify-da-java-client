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

import static com.redhat.exhort.image.ImageUtils.getImageDigests;
import static com.redhat.exhort.image.ImageUtils.getImagePlatform;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public class ImageRef {

  public static final String OCI_TYPE = "oci";
  public static final String REPOSITORY_QUALIFIER = "repository_url";
  public static final String TAG_QUALIFIER = "tag";
  public static final String ARCH_QUALIFIER = "arch";
  public static final String OS_QUALIFIER = "os";
  public static final String VARIANT_QUALIFIER = "variant";

  private final Image image;
  private Platform platform;

  public ImageRef(String image, String platform) {
    this.image = new Image(image);

    if (platform != null) {
      this.platform = new Platform(platform);
    }

    checkImageDigest();
  }

  public ImageRef(PackageURL packageURL) {
    String name;
    String version;
    String tag = null;
    String repositoryRrl = null;
    String arch = null;
    String os = null;
    String variant = null;

    Map<String, String> qualifiers = packageURL.getQualifiers();
    if (qualifiers != null && !qualifiers.isEmpty()) {
      repositoryRrl = qualifiers.get(REPOSITORY_QUALIFIER);
      tag = qualifiers.get(TAG_QUALIFIER);
      arch = qualifiers.get(ARCH_QUALIFIER);
      os = qualifiers.get(OS_QUALIFIER);
      variant = qualifiers.get(VARIANT_QUALIFIER);
    }
    name = packageURL.getName();
    version = packageURL.getVersion();

    String imageName = name;
    if (repositoryRrl != null) {
      imageName = repositoryRrl;
    }
    if (tag != null) {
      imageName = imageName + ":" + tag;
    }
    if (version != null) {
      imageName = imageName + "@" + version;
    }

    this.image = new Image(imageName);

    if (arch != null && os != null) {
      this.platform = new Platform(os, arch, variant);
    }
  }

  public Image getImage() {
    return image;
  }

  public Platform getPlatform() {
    return platform;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    ImageRef imageRef = (ImageRef) o;
    return Objects.equals(image, imageRef.image) && Objects.equals(platform, imageRef.platform);
  }

  @Override
  public int hashCode() {
    return Objects.hash(image, platform);
  }

  @Override
  public String toString() {
    return "ImageRef{" + "image='" + image + '\'' + ", platform='" + platform + '\'' + '}';
  }

  void checkImageDigest() {
    if (this.image.getDigest() == null) {
      try {
        var digests = getImageDigests(this);
        if (digests.isEmpty()) {
          throw new RuntimeException("Failed to get any image digest");
        }
        if (digests.size() == 1 && digests.containsKey(Platform.EMPTY_PLATFORM)) {
          this.image.setDigest(digests.get(Platform.EMPTY_PLATFORM));
        } else {
          if (this.platform == null) {
            this.platform = getImagePlatform();
          }
          if (this.platform == null) {
            throw new RuntimeException("Failed to get image platform for image digest");
          }
          if (!digests.containsKey(this.platform)) {
            throw new RuntimeException(
                String.format("Failed to get image digest for platform %s", this.platform));
          }
          this.image.setDigest(digests.get(this.platform));
        }
      } catch (JsonProcessingException | IllegalArgumentException ex) {
        throw new RuntimeException("Failed to get image digest", ex);
      }
    }
  }

  // https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#oci
  public PackageURL getPackageURL() throws MalformedPackageURLException {
    TreeMap<String, String> qualifiers = new TreeMap<>();
    var repositoryUrl = this.image.getNameWithoutTag();
    var simpleName = this.image.getSimpleName();
    if (repositoryUrl != null && !repositoryUrl.equalsIgnoreCase(simpleName)) {
      qualifiers.put(REPOSITORY_QUALIFIER, repositoryUrl.toLowerCase());
    }
    if (this.platform != null) {
      qualifiers.put(ARCH_QUALIFIER, this.platform.getArchitecture().toLowerCase());
      qualifiers.put(OS_QUALIFIER, this.platform.getOs().toLowerCase());
      if (this.platform.getVariant() != null) {
        qualifiers.put(VARIANT_QUALIFIER, this.platform.getVariant().toLowerCase());
      }
    }
    var tag = this.image.getTag();
    if (tag != null) {
      qualifiers.put(TAG_QUALIFIER, tag);
    }

    return new PackageURL(
        OCI_TYPE,
        null,
        this.image.getSimpleName().toLowerCase(),
        image.getDigest().toLowerCase(),
        qualifiers,
        null);
  }
}
