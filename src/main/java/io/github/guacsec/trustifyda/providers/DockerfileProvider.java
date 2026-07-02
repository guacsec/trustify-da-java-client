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

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.image.ImageUtils;
import io.github.guacsec.trustifyda.tools.Ecosystem.Type;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Provider for Dockerfile and Containerfile manifests. Parses the FROM instruction to extract the
 * base image reference, then uses syft to generate a CycloneDX SBOM for analysis.
 */
public final class DockerfileProvider extends Provider {

  private static final Pattern FROM_LINE_PATTERN =
      Pattern.compile("^FROM\\s+", Pattern.CASE_INSENSITIVE);

  public DockerfileProvider(Path manifest) {
    super(Type.DOCKERFILE, manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    return generateSbomContent();
  }

  @Override
  public Content provideComponent() throws IOException {
    return generateSbomContent();
  }

  @Override
  public String readLicenseFromManifest() {
    return null;
  }

  /**
   * Parses the manifest file to find the last FROM instruction and generates a CycloneDX SBOM for
   * the referenced image.
   */
  private Content generateSbomContent() throws IOException {
    String imageReference = parseLastFromImage(manifestPath);
    ImageRef imageRef = ImageUtils.parseImageRef(imageReference);
    try {
      var sbomNode = ImageUtils.generateImageSBOM(imageRef);
      byte[] sbomBytes = objectMapper.writeValueAsBytes(sbomNode);
      return new Content(sbomBytes, Api.CYCLONEDX_MEDIA_TYPE);
    } catch (Exception e) {
      throw new IOException("Failed to generate SBOM for image: " + imageReference, e);
    }
  }

  /**
   * Parses a Dockerfile/Containerfile and extracts the image reference from the last FROM
   * instruction. In multi-stage builds, the last FROM defines the final image.
   *
   * @param dockerfile path to the Dockerfile or Containerfile
   * @return the image reference string from the last FROM instruction
   * @throws IOException if the file cannot be read or contains no FROM instruction
   */
  static String parseLastFromImage(Path dockerfile) throws IOException {
    List<String> lines = Files.readAllLines(dockerfile);
    String lastImage = null;
    for (String line : lines) {
      String trimmed = line.trim();
      var matcher = FROM_LINE_PATTERN.matcher(trimmed);
      if (matcher.find()) {
        // Strip the FROM keyword, then tokenize the remainder
        String remainder = trimmed.substring(matcher.end());
        String[] tokens = remainder.split("\\s+");
        // Skip all leading --flag tokens (e.g. --platform=linux/amd64 --some-flag=value)
        int i = 0;
        while (i < tokens.length && tokens[i].startsWith("--")) {
          i++;
        }
        if (i < tokens.length) {
          lastImage = tokens[i];
        }
      }
    }
    if (lastImage == null) {
      throw new IOException("No FROM instruction found in " + dockerfile);
    }
    if (lastImage.contains("${")) {
      throw new IOException(
          "Dockerfile uses ARG substitution in FROM line — cannot resolve variable references: "
              + dockerfile);
    }
    if ("scratch".equals(lastImage)) {
      throw new IOException(
          "Dockerfile uses FROM scratch — no base image to analyze: " + dockerfile);
    }
    return lastImage;
  }
}
