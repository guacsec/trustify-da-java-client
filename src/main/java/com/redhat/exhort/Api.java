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
package com.redhat.exhort;

import com.redhat.exhort.api.v4.AnalysisReport;
import com.redhat.exhort.image.ImageRef;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/** The Api interface is used for contracting API implementations. * */
public interface Api {

  String CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json";

  enum MediaType {
    APPLICATION_JSON,
    TEXT_HTML,
    MULTIPART_MIXED;

    @Override
    public String toString() {
      return this.name().toLowerCase().replace("_", "/");
    }
  }

  /** POJO class used for aggregating multipart/mixed analysis requests. */
  class MixedReport {
    public final byte[] html;
    public final AnalysisReport json;

    public MixedReport(final byte[] html, final AnalysisReport json) {
      this.html = html;
      this.json = json;
    }

    public MixedReport() {
      this.html = new byte[0];
      this.json = new AnalysisReport();
    }

    @Override
    public boolean equals(final Object o) {
      if (this == o) return true;
      if (o == null || this.getClass() != o.getClass()) return false;
      var that = (MixedReport) o;
      return Arrays.equals(this.html, that.html) && Objects.equals(this.json, that.json);
    }

    @Override
    public int hashCode() {
      return 31 * Objects.hash(json) + Arrays.hashCode(html);
    }
  }

  /**
   * Use for creating a stack analysis HTML report for a given manifest file.
   *
   * @param manifestFile the path for the manifest file
   * @return a mixed reports for both HTML and JSON wrapped in a CompletableFuture
   * @throws IOException when failed to load the manifest file
   */
  CompletableFuture<MixedReport> stackAnalysisMixed(String manifestFile) throws IOException;

  /**
   * Use for creating a stack analysis HTML report for a given manifest file.
   *
   * @param manifestFile the path for the manifest file
   * @return the HTML report as a String wrapped in a CompletableFuture
   * @throws IOException when failed to load the manifest file
   */
  CompletableFuture<byte[]> stackAnalysisHtml(String manifestFile) throws IOException;

  /**
   * Use for creating a stack analysis deserialized Json report for a given manifest file.
   *
   * @param manifestFile the path for the manifest file
   * @return the deserialized Json report as an AnalysisReport wrapped in a CompletableFuture
   * @throws IOException when failed to load the manifest file
   */
  CompletableFuture<AnalysisReport> stackAnalysis(String manifestFile) throws IOException;

  /**
   * Use for creating a component analysis deserialized Json report for a given type and content.
   *
   * @param manifest the path of the manifest, example {@code /path/to/pom.xml}
   * @param manifestContent a byte array of the manifest's content
   * @return the deserialized Json report as an AnalysisReport wrapped in a CompletableFuture
   * @throws IOException when failed to load the manifest content
   */
  CompletableFuture<AnalysisReport> componentAnalysis(String manifest, byte[] manifestContent)
      throws IOException;

  CompletableFuture<AnalysisReport> componentAnalysis(String manifest) throws IOException;

  CompletableFuture<Map<ImageRef, AnalysisReport>> imageAnalysis(Set<ImageRef> imageRefs)
      throws IOException;

  CompletableFuture<byte[]> imageAnalysisHtml(Set<ImageRef> imageRefs) throws IOException;
}
