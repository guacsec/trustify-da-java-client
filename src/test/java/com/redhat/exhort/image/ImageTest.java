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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ImageTest {

  static Stream<Arguments> imageTestSources() {
    return Stream.of(
        Arguments.of(
            Named.of(
                "full name, host port",
                "test-host:5000/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            null,
            "optional-host:2500",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            "test-host:5000",
            "test-namespace/test-repository",
            "test-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-host:5000/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            true,
            "test-host:5000/test-namespace/test-repository",
            "test-host:5000/test-namespace/test-repository",
            "test-host:5000/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-host:5000/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace",
            "test-repository",
            "optional-host:2500/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-host:5000/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "full name, registry",
                "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            "test.io",
            "test-namespace/test-repository",
            "test-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            true,
            "test.io/test-namespace/test-repository",
            "test.io/test-namespace/test-repository",
            "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace",
            "test-repository",
            "optional.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "without registry",
                "test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-namespace/test-repository",
            "test-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            false,
            "test-namespace/test-repository",
            "optional.io/test-namespace/test-repository",
            "test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "optional.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace",
            "test-repository",
            "optional.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "without namepsace",
                "test.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            "test.io",
            "test-repository",
            "test-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            true,
            "test.io/test-repository",
            "test.io/test-repository",
            "test.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            null,
            "test-repository",
            "optional.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "without registry, namespace",
                "test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "test-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "optional.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            null,
            "test-repository",
            "optional.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of("without registry, namespace, digest", "test-repository:test-tag"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "test-tag",
            null,
            "test-repository:test-tag",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:test-tag",
            "optional.io/test-repository:test-tag",
            null,
            "test-repository",
            "optional.io/test-repository:test-tag",
            "test-repository:test-tag@sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0"),
        Arguments.of(
            Named.of(
                "without registry, namespace, tag",
                "test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            null,
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "optional.io/test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            null,
            "test-repository",
            "optional.io/test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of("without registry, namespace, tag, digest", "test-repository"),
            null,
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "latest",
            null,
            "test-repository:latest",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:latest",
            "optional.io/test-repository:latest",
            null,
            "test-repository",
            "optional.io/test-repository:latest",
            "test-repository:latest@sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0"),
        Arguments.of(
            Named.of(
                "given tag, full name, host port",
                "test-host:5000/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            "alt-tag",
            "optional-host:2500",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            "test-host:5000",
            "test-namespace/test-repository",
            "alt-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-host:5000/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            true,
            "test-host:5000/test-namespace/test-repository",
            "test-host:5000/test-namespace/test-repository",
            "test-host:5000/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-host:5000/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace",
            "test-repository",
            "optional-host:2500/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-host:5000/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "given tag, full name, registry",
                "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            "test.io",
            "test-namespace/test-repository",
            "alt-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            true,
            "test.io/test-namespace/test-repository",
            "test.io/test-namespace/test-repository",
            "test.io/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace",
            "test-repository",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "given tag, without registry",
                "test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-namespace/test-repository",
            "alt-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            false,
            "test-namespace/test-repository",
            "optional.io/test-namespace/test-repository",
            "test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "optional.io/test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace",
            "test-repository",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-namespace/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "given tag, without namepsace",
                "test.io/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            "test.io",
            "test-repository",
            "alt-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            true,
            "test.io/test-repository",
            "test.io/test-repository",
            "test.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            null,
            "test-repository",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of(
                "given tag, without registry, namespace",
                "test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "alt-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            null,
            "test-repository",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of("given tag, without registry, namespace, digest", "test-repository:test-tag"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "alt-tag",
            null,
            "test-repository:alt-tag",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:alt-tag",
            "optional.io/test-repository:alt-tag",
            null,
            "test-repository",
            "optional.io/test-repository:alt-tag",
            "test-repository:alt-tag@sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0"),
        Arguments.of(
            Named.of(
                "given tag, without registry, namespace, tag",
                "test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "alt-tag",
            "sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            null,
            "test-repository",
            "optional.io/test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf",
            "test-repository:alt-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf"),
        Arguments.of(
            Named.of("given tag, without registry, namespace, tag, digest", "test-repository"),
            "alt-tag",
            "optional.io",
            "sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0",
            null,
            "test-repository",
            "alt-tag",
            null,
            "test-repository:alt-tag",
            false,
            "test-repository",
            "optional.io/test-repository",
            "test-repository:alt-tag",
            "optional.io/test-repository:alt-tag",
            null,
            "test-repository",
            "optional.io/test-repository:alt-tag",
            "test-repository:alt-tag@sha256:b048f7d88a830ba5b7c690193644f6baf658dde41d5d1e70d9f4bc275865a9a0"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("imageTestSources")
  void test_image_no_tag(
      String fullName,
      String givenTag,
      String optionalRegistry,
      String optionalDigest,
      String expectedRegistry,
      String expectedRepository,
      String expectedTag,
      String expectedDigest,
      String expectedString,
      boolean expectedHasRegistry,
      String expectedNameWithoutTag,
      String expectedNameWithoutTagOptionalRegistry,
      String expectedFullName,
      String expectedFullNameOptionalRegistry,
      String expectedUser,
      String expectedSimpleName,
      String expectedNameWithOptionalRepository,
      String expectedFullNameOptionalDigest) {

    var image = givenTag == null ? new Image(fullName) : new Image(fullName, givenTag);

    assertEquals(expectedRegistry, image.getRegistry());
    assertEquals(expectedRepository, image.getRepository());
    assertEquals(expectedTag, image.getTag());
    assertEquals(expectedDigest, image.getDigest());
    assertEquals(expectedString, image.toString());
    assertEquals(expectedHasRegistry, image.hasRegistry());
    assertEquals(expectedNameWithoutTag, image.getNameWithoutTag());
    assertEquals(expectedNameWithoutTagOptionalRegistry, image.getNameWithoutTag(optionalRegistry));
    assertEquals(expectedFullName, image.getFullName());
    assertEquals(expectedFullNameOptionalRegistry, image.getFullName(optionalRegistry));
    assertEquals(expectedUser, image.getUser());
    assertEquals(expectedSimpleName, image.getSimpleName());
    assertEquals(
        expectedNameWithOptionalRepository, image.getNameWithOptionalRepository(optionalRegistry));
    assertEquals(expectedFullName, image.getNameWithOptionalRepository(null));

    image.setDigest(optionalDigest);
    assertEquals(expectedFullNameOptionalDigest, image.getFullName());
  }

  @Test
  void test_equals() {
    var image1 = new Image("test-image");
    var image2 = new Image("test-image:latest");
    var image3 = new Image("test-image:old");

    assertEquals(image1, image2);
    assertNotEquals(image2, image3);
  }

  @Test
  void test_hashCode() {
    var image1 = new Image("test-image");
    var image2 = new Image("test-image:latest");
    var image3 = new Image("test-image:old");

    assertEquals(image1.hashCode(), image2.hashCode());
    assertNotEquals(image2.hashCode(), image3.hashCode());
  }

  @Test
  void test_image_null() {
    var expectedMessage = "Image name must not be null";

    var exception1 = assertThrows(NullPointerException.class, () -> new Image(null));
    assertEquals(expectedMessage, exception1.getMessage());

    var exception2 = assertThrows(NullPointerException.class, () -> new Image(null, "test"));
    assertEquals(expectedMessage, exception2.getMessage());

    var exception3 = assertThrows(NullPointerException.class, () -> Image.validate(null));
    assertEquals(expectedMessage, exception3.getMessage());
  }

  @Test
  void test_image_invalid() {
    var imageName = "";
    var expectedMessage = imageName + " is not a proper image name ([registry/][repo][:port]";

    var exception1 = assertThrows(IllegalArgumentException.class, () -> new Image(imageName));
    assertEquals(expectedMessage, exception1.getMessage());

    var exception2 =
        assertThrows(IllegalArgumentException.class, () -> new Image(imageName, "test"));
    assertEquals(expectedMessage, exception2.getMessage());

    var exception3 = assertThrows(IllegalArgumentException.class, () -> Image.validate(imageName));
    assertEquals(expectedMessage, exception3.getMessage());
  }

  @Test
  void test_all_invalid() {
    var imageName =
        "%&^.%*/*(*&(/&(&(&:&^*&@sha256:333224A233DB31852AC1085C6CD702016AB8AAF54CECDE5C4BED5451D636ADCF";
    var expectedMessage =
        "Given Docker name"
            + " '%&^.%*/*(*&(/&(&(&:&^*&@sha256:333224A233DB31852AC1085C6CD702016AB8AAF54CECDE5C4BED5451D636ADCF'"
            + " is invalid:\n"
            + "   * registry part '%&^.%*' doesn't match allowed pattern"
            + " '^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*(?::[0-9]+)?$'\n"
            + "   * image part '&(&(&' doesn't match allowed pattern"
            + " '[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?'\n"
            + "   * user part '*(*&(' doesn't match allowed pattern"
            + " '[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?'\n"
            + "   * tag part '&^*&' doesn't match allowed pattern '^[\\w][\\w.-]{0,127}$'\n"
            + "   * digest part"
            + " 'sha256:333224A233DB31852AC1085C6CD702016AB8AAF54CECDE5C4BED5451D636ADCF' doesn't"
            + " match allowed pattern '^sha256:[a-z0-9]{32,}$'\n"
            + "See http://bit.ly/docker_image_fmt for more details";

    var exception1 = assertThrows(IllegalArgumentException.class, () -> new Image(imageName));
    assertEquals(expectedMessage, exception1.getMessage());

    var exception2 =
        assertThrows(IllegalArgumentException.class, () -> new Image(imageName, "&^*&"));
    assertEquals(expectedMessage, exception2.getMessage());

    var exception3 = assertThrows(IllegalArgumentException.class, () -> Image.validate(imageName));
    assertEquals(expectedMessage, exception3.getMessage());
  }
}
