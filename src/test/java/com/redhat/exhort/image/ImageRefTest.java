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
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.redhat.exhort.ExhortTest;
import com.redhat.exhort.tools.Operations;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class ImageRefTest extends ExhortTest {

  @Test
  void test_imageRef() throws MalformedPackageURLException {
    var image =
        "test.io/test-namespace/test-repository:test-tag@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf";
    var platform = "linux/arm/v7";

    var imageRef = new ImageRef(image, platform);

    assertEquals(new Image(image), imageRef.getImage());
    assertEquals(new Platform(platform), imageRef.getPlatform());
    assertEquals(
        "ImageRef{image='" + image + '\'' + ", platform='" + platform + '\'' + '}',
        imageRef.toString());

    var purl =
        new PackageURL(
            "pkg:oci/test-repository@sha256:333224a233db31852ac1085c6cd702016ab8aaf54cecde5c4bed5451d636adcf?"
                + "repository_url=test.io/test-namespace/test-repository&tag=test-tag&os=linux&arch=arm&variant=v7");
    assertEquals(purl, imageRef.getPackageURL());

    var imageRefPurl = new ImageRef(purl);
    assertEquals(imageRef, imageRefPurl);
    assertEquals(imageRef, imageRefPurl);
    assertEquals(imageRef.hashCode(), imageRefPurl.hashCode());
  }

  @Test
  void test_check_image_digest() throws IOException {
    try (MockedStatic<Operations> mock = Mockito.mockStatic(Operations.class);
        var is =
            getResourceAsStreamDecision(
                this.getClass(), "msc/image/skopeo_inspect_multi_raw.json")) {
      var json =
          new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))
              .lines()
              .collect(Collectors.joining("\n"));
      var output = new Operations.ProcessExecOutput(json, "", 0);
      var imageName = "test.io/test/test-app:test-version";

      mock.when(() -> Operations.getCustomPathOrElse(eq("skopeo"))).thenReturn("skopeo");

      mock.when(() -> Operations.getExecutable(eq("skopeo"), any())).thenReturn("skopeo");

      mock.when(
              () ->
                  Operations.runProcessGetFullOutput(
                      isNull(),
                      aryEq(
                          new String[] {
                            "skopeo", "inspect", "--raw", String.format("docker://%s", imageName)
                          }),
                      isNull()))
          .thenReturn(output);

      mock.when(() -> Operations.getCustomPathOrElse(eq("docker"))).thenReturn("docker");

      mock.when(() -> Operations.getExecutable(eq("docker"), any())).thenReturn("docker");

      mock.when(
              () ->
                  Operations.runProcessGetFullOutput(
                      isNull(), aryEq(new String[] {"docker", "info"}), isNull()))
          .thenReturn(
              new Operations.ProcessExecOutput("OSType: linux\nArchitecture: amd64", "", 0));

      var imageRef = new ImageRef(imageName, null);
      imageRef.checkImageDigest();

      var expectedImageRef =
          new ImageRef(
              imageName
                  + "@sha256:06d06f15f7b641a78f2512c8817cbecaa1bf549488e273f5ac27ff1654ed33f0",
              "linux/amd64");

      assertEquals(expectedImageRef, imageRef);
    }
  }
}
