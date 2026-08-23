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

import com.fasterxml.jackson.databind.JsonNode;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.image.ImageUtils;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.tools.Ecosystem.Type;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provider for Dockerfile and Containerfile manifests. Parses all FROM instructions to extract base
 * image references, then uses syft to generate CycloneDX SBOMs for batch analysis.
 */
public final class DockerfileProvider extends Provider {

  private static final Logger LOG = LoggersFactory.getLogger(DockerfileProvider.class.getName());

  private static final Pattern FROM_LINE_PATTERN =
      Pattern.compile("^FROM\\s+", Pattern.CASE_INSENSITIVE);

  private static final Pattern ARG_LINE_PATTERN =
      Pattern.compile("^ARG\\s+([A-Za-z_][A-Za-z0-9_]*)=(.+)", Pattern.CASE_INSENSITIVE);

  private static final Pattern VAR_REF_PATTERN =
      Pattern.compile("\\$\\{([^}]+)}|\\$([A-Za-z_][A-Za-z0-9_]*)");

  public DockerfileProvider(Path manifest) {
    super(Type.DOCKERFILE, manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    return generateBatchSbomContent();
  }

  @Override
  public Content provideComponent() throws IOException {
    return generateBatchSbomContent();
  }

  @Override
  public String readLicenseFromManifest() {
    return null;
  }

  /**
   * Parses the manifest file to find all FROM instructions and generates a CycloneDX SBOM for each
   * image. Returns batch content as a JSON object mapping purls to SBOM objects.
   */
  private Content generateBatchSbomContent() throws IOException {
    List<String> imageReferences = parseAllFromImages(manifestPath);
    Map<String, JsonNode> purlToSbom = new LinkedHashMap<>();
    for (String imageReference : imageReferences) {
      try {
        ImageRef imageRef = ImageUtils.parseImageRef(imageReference);
        JsonNode sbomNode = ImageUtils.generateImageSBOM(imageRef);
        String purl = imageRef.getPackageURL().toString();
        purlToSbom.put(purl, sbomNode);
      } catch (Exception e) {
        LOG.warning(
            String.format("Skipping image %s due to error: %s", imageReference, e.getMessage()));
      }
    }
    if (purlToSbom.isEmpty()) {
      throw new IOException("No analyzable FROM images found in " + manifestPath);
    }
    byte[] batchBytes =
        objectMapper.writeValueAsString(purlToSbom).getBytes(StandardCharsets.UTF_8);
    return new Content(batchBytes, Api.CYCLONEDX_MEDIA_TYPE, true);
  }

  /**
   * Parses a Dockerfile/Containerfile and returns {@link ImageRef} objects for all FROM images.
   * Reuses {@link #parseAllFromImages(Path)} for FROM extraction and ARG resolution, then converts
   * each image string to an {@link ImageRef} via {@link ImageUtils#parseImageRef(String)}.
   *
   * @param dockerfile path to the Dockerfile or Containerfile
   * @return set of image references preserving FROM order
   * @throws IOException if the file cannot be read or no images are analyzable
   */
  public static Set<ImageRef> parseImageRefs(Path dockerfile) throws IOException {
    List<String> imageReferences = parseAllFromImages(dockerfile);
    Set<ImageRef> imageRefs = new LinkedHashSet<>();
    for (String imageReference : imageReferences) {
      try {
        ImageRef imageRef = ImageUtils.parseImageRef(imageReference);
        imageRefs.add(imageRef);
      } catch (Exception e) {
        LOG.warning(
            String.format("Skipping image %s due to error: %s", imageReference, e.getMessage()));
      }
    }
    if (imageRefs.isEmpty()) {
      throw new IOException("No analyzable FROM images found in " + dockerfile);
    }
    return imageRefs;
  }

  /**
   * Parses a Dockerfile/Containerfile and extracts image references from all FROM instructions.
   * Resolves ARG substitutions using default values when available. Skips FROM lines with
   * unresolvable ARG references (no default value) or that reference {@code scratch}.
   *
   * @param dockerfile path to the Dockerfile or Containerfile
   * @return list of image reference strings from all valid FROM instructions
   * @throws IOException if the file cannot be read or contains no analyzable FROM instruction
   */
  static List<String> parseAllFromImages(Path dockerfile) throws IOException {
    List<String> lines = Files.readAllLines(dockerfile);
    Map<String, String> argDefaults = new HashMap<>();
    List<String> images = new ArrayList<>();
    for (String line : lines) {
      String trimmed = line.trim();
      var argMatcher = ARG_LINE_PATTERN.matcher(trimmed);
      if (argMatcher.find()) {
        String val = argMatcher.group(2).trim();
        if ((val.startsWith("\"") && val.endsWith("\""))
            || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.substring(1, val.length() - 1);
        }
        argDefaults.put(argMatcher.group(1), val);
        continue;
      }
      var fromMatcher = FROM_LINE_PATTERN.matcher(trimmed);
      if (fromMatcher.find()) {
        String remainder = trimmed.substring(fromMatcher.end());
        String[] tokens = remainder.split("\\s+");
        int i = 0;
        while (i < tokens.length && tokens[i].startsWith("--")) {
          i++;
        }
        if (i < tokens.length) {
          String image = tokens[i];
          if (image.contains("$")) {
            image = resolveArgSubstitutions(image, argDefaults);
            if (image == null) {
              LOG.info(
                  String.format(
                      "Skipping FROM line with unresolvable ARG in %s: %s", dockerfile, tokens[i]));
              continue;
            }
          }
          if ("scratch".equalsIgnoreCase(image)) {
            LOG.info(String.format("Skipping FROM scratch in %s", dockerfile));
            continue;
          }
          images.add(image);
        }
      }
    }
    if (images.isEmpty()) {
      throw new IOException("No analyzable FROM instruction found in " + dockerfile);
    }
    return images;
  }

  /**
   * Resolves {@code ${VAR}} and {@code $VAR} references in an image string using collected ARG
   * defaults.
   *
   * @return the resolved image string, or {@code null} if any variable has no default value
   */
  private static String resolveArgSubstitutions(String image, Map<String, String> argDefaults) {
    Matcher varMatcher = VAR_REF_PATTERN.matcher(image);
    StringBuilder sb = new StringBuilder();
    while (varMatcher.find()) {
      String varName = varMatcher.group(1) != null ? varMatcher.group(1) : varMatcher.group(2);
      String defaultValue = argDefaults.get(varName);
      if (defaultValue == null) {
        return null;
      }
      varMatcher.appendReplacement(sb, Matcher.quoteReplacement(defaultValue));
    }
    varMatcher.appendTail(sb);
    return sb.toString();
  }
}
