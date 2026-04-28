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
package io.github.guacsec.trustifyda.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ComponentAnalysisResult;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.image.ImageUtils;
import io.github.guacsec.trustifyda.license.LicenseCheck;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.providers.JavaMavenProvider;
import io.github.guacsec.trustifyda.providers.golang.model.GoWorkspace;
import io.github.guacsec.trustifyda.providers.javascript.workspace.JsWorkspaceDiscovery;
import io.github.guacsec.trustifyda.providers.rust.model.CargoMetadata;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.tools.Operations;
import io.github.guacsec.trustifyda.utils.Environment;
import io.github.guacsec.trustifyda.utils.PyprojectTomlUtils;
import io.github.guacsec.trustifyda.utils.WorkspaceUtils;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

/** Concrete implementation of the Exhort {@link Api} Service. */
public final class ExhortApi implements Api {

  private static final String HTTP_VERSION_TRUSTIFY_DA_CLIENT = "HTTP_VERSION_TRUSTIFY_DA_CLIENT";

  private static final String TRUSTIFY_DA_PROXY_URL = "TRUSTIFY_DA_PROXY_URL";

  private static final Logger LOG = LoggersFactory.getLogger(ExhortApi.class.getName());

  private static final String TRUSTIFY_DA_BACKEND_URL = "TRUSTIFY_DA_BACKEND_URL";
  public static final String TRUST_DA_TOKEN_HEADER = "trust-da-token";
  public static final String TRUST_DA_SOURCE_HEADER = "trust-da-source";
  public static final String TRUST_DA_OPERATION_TYPE_HEADER = "trust-da-operation-type";
  public static final String TRUSTIFY_DA_REQUEST_ID_HEADER_NAME = "ex-request-id";
  public static final String S_API_V_5_ANALYSIS = "%s/api/v5/analysis";
  public static final String S_API_V_5_BATCH_ANALYSIS = "%s/api/v5/batch-analysis";
  public static final String S_API_V5_LICENSES = "%s/api/v5/licenses/%s";
  public static final String S_API_V5_LICENSES_IDENTIFY = "%s/api/v5/licenses/identify";
  private static final String TRUSTIFY_DA_LICENSE_CHECK = "TRUSTIFY_DA_LICENSE_CHECK";

  private String endpoint;

  public String getEndpoint() {
    if (this.endpoint == null) {
      this.endpoint = getExhortUrl();
    }
    return this.endpoint;
  }

  private final HttpClient client;
  private final ObjectMapper mapper;

  private LocalDateTime startTime;
  private LocalDateTime providerEndTime;
  private LocalDateTime endTime;

  public ExhortApi() {
    this(createHttpClient());
  }

  /**
   * Get the HTTP protocol Version set by client in environment variable, if not set, the default is
   * HTTP Protocol Version 1.1
   *
   * @return i.e. HttpClient.Version.HTTP_1.1
   */
  static HttpClient.Version getHttpVersion() {
    var version = Environment.get(HTTP_VERSION_TRUSTIFY_DA_CLIENT);
    return (version != null && version.contains("2"))
        ? HttpClient.Version.HTTP_2
        : HttpClient.Version.HTTP_1_1;
  }

  ExhortApi(final HttpClient client) {
    commonHookBeginning(true);
    this.client = client;
    this.mapper = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
  }

  public static HttpClient createHttpClient() {
    HttpClient.Builder builder = HttpClient.newBuilder().version(getHttpVersion());
    String proxyUrl = Environment.get(TRUSTIFY_DA_PROXY_URL);
    if (proxyUrl != null && !proxyUrl.isBlank()) {
      try {
        URI proxyUri = URI.create(proxyUrl);
        builder.proxy(
            ProxySelector.of(new InetSocketAddress(proxyUri.getHost(), proxyUri.getPort())));
      } catch (IllegalArgumentException e) {
        LOG.warning("Invalid TRUSTIFY_DA_PROXY_URL: " + proxyUrl + ", using direct connection");
      }
    }
    return builder.build();
  }

  private String commonHookBeginning(boolean startOfApi) {
    if (startOfApi) {
      if (debugLoggingIsNeeded()) {
        LOG.info("Start of trustify-da-java-client");
        LOG.info(String.format("Starting time of API: %s", LocalDateTime.now()));
      }
    } else {
      if (Objects.isNull(getClientRequestId())) {
        generateClientRequestId();
      }
      if (debugLoggingIsNeeded()) {

        this.startTime = LocalDateTime.now();

        LOG.info(String.format("Starting time: %s", this.startTime));
      }
    }
    return getClientRequestId();
  }

  private static void generateClientRequestId() {
    RequestManager.getInstance().addClientTraceIdToRequest(UUID.randomUUID().toString());
  }

  private static String getClientRequestId() {
    return RequestManager.getInstance().getTraceIdOfRequest();
  }

  private String getExhortUrl() {
    String endpoint = Environment.get(TRUSTIFY_DA_BACKEND_URL);
    if (endpoint == null || endpoint.trim().isEmpty()) {
      throw new IllegalStateException(
          "Backend URL not configured. Please set the TRUSTIFY_DA_BACKEND_URL environment"
              + " variable.");
    }
    endpoint = endpoint.trim();

    if (debugLoggingIsNeeded()) {
      LOG.info(
          String.format(
              "Backend URL configured - TRUSTIFY_DA_BACKEND_URL=%s",
              Environment.get(TRUSTIFY_DA_BACKEND_URL)));
    }
    return endpoint;
  }

  @Override
  public CompletableFuture<MixedReport> stackAnalysisMixed(final String manifestFile)
      throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    return this.client
        .sendAsync(
            this.buildStackRequest(manifestFile, MediaType.MULTIPART_MIXED),
            HttpResponse.BodyHandlers.ofByteArray())
        .thenApply(
            resp -> {
              RequestManager.getInstance().addClientTraceIdToRequest(exClientTraceId);
              if (debugLoggingIsNeeded()) {
                logExhortRequestId(resp);
              }
              if (resp.statusCode() == 200) {
                byte[] htmlPart = null;
                AnalysisReport jsonPart = null;
                var ds = new ByteArrayDataSource(resp.body(), MediaType.MULTIPART_MIXED.toString());
                try {
                  var mp = new MimeMultipart(ds);
                  for (var i = 0; i < mp.getCount(); i++) {
                    if (Objects.isNull(htmlPart)
                        && MediaType.TEXT_HTML
                            .toString()
                            .equals(mp.getBodyPart(i).getContentType())) {
                      htmlPart = mp.getBodyPart(i).getInputStream().readAllBytes();
                    }
                    if (Objects.isNull(jsonPart)
                        && MediaType.APPLICATION_JSON
                            .toString()
                            .equals(mp.getBodyPart(i).getContentType())) {
                      jsonPart =
                          this.mapper.readValue(
                              mp.getBodyPart(i).getInputStream().readAllBytes(),
                              AnalysisReport.class);
                    }
                  }
                } catch (IOException | MessagingException e) {
                  throw new RuntimeException(e);
                }
                commonHookAfterExhortResponse();
                return new MixedReport(
                    Objects.requireNonNull(htmlPart), Objects.requireNonNull(jsonPart));
              } else {
                LOG.severe(
                    String.format(
                        "failed to invoke stackAnalysisMixed for getting the html and json reports,"
                            + " Http Response Status=%s , received message from server= %s ",
                        resp.statusCode(), new String(resp.body())));
                return new MixedReport();
              }
            });
  }

  @Override
  public CompletableFuture<byte[]> stackAnalysisHtml(final String manifestFile) throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    return this.client
        .sendAsync(
            this.buildStackRequest(manifestFile, MediaType.TEXT_HTML),
            HttpResponse.BodyHandlers.ofByteArray())
        .thenApply(
            httpResponse -> {
              RequestManager.getInstance().addClientTraceIdToRequest(exClientTraceId);
              if (debugLoggingIsNeeded()) {
                logExhortRequestId(httpResponse);
              }
              if (httpResponse.statusCode() != 200) {
                LOG.severe(
                    String.format(
                        "failed to invoke stackAnalysis for getting the html report, Http Response"
                            + " Status=%s , received message from server= %s ",
                        httpResponse.statusCode(), new String(httpResponse.body())));
              }
              commonHookAfterExhortResponse();
              return httpResponse.body();
            })
        .exceptionally(
            exception -> {
              LOG.severe(
                  String.format(
                      "failed to invoke stackAnalysis for getting the html report, received"
                          + " message= %s ",
                      exception.getMessage()));
              //      LOG.log(System.Logger.Level.ERROR, "Exception Entity", exception);
              commonHookAfterExhortResponse();
              return new byte[0];
            });
  }

  @Override
  public CompletableFuture<AnalysisReport> stackAnalysis(final String manifestFile)
      throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    return this.client
        .sendAsync(
            this.buildStackRequest(manifestFile, MediaType.APPLICATION_JSON),
            HttpResponse.BodyHandlers.ofString())
        .thenApply(
            response ->
                getAnalysisReportFromResponse(response, "StackAnalysis", "json", exClientTraceId))
        .exceptionally(
            exception -> {
              LOG.severe(
                  String.format(
                      "failed to invoke stackAnalysis for getting the json report, received"
                          + " message= %s ",
                      exception.getMessage()));
              return new AnalysisReport();
            });
  }

  private AnalysisReport getAnalysisReportFromResponse(
      HttpResponse<String> response, String operation, String reportName, String exClientTraceId) {
    RequestManager.getInstance().addClientTraceIdToRequest(exClientTraceId);
    if (debugLoggingIsNeeded()) {
      logExhortRequestId(response);
    }
    if (response.statusCode() == 200) {
      if (debugLoggingIsNeeded()) {
        LOG.info(
            String.format(
                "Response body received from exhort server : %s %s",
                System.lineSeparator(), response.body()));
      }
      commonHookAfterExhortResponse();
      try {

        return this.mapper.readValue(response.body(), AnalysisReport.class);
      } catch (JsonProcessingException e) {
        throw new CompletionException(e);
      }

    } else {
      LOG.severe(
          String.format(
              "failed to invoke %s for getting the %s report, Http Response Status=%s , received"
                  + " message from server= %s ",
              operation, reportName, response.statusCode(), response.body()));
      return new AnalysisReport();
    }
  }

  private static void logExhortRequestId(HttpResponse<?> response) {
    Optional<String> headerExRequestId =
        response.headers().allValues(TRUSTIFY_DA_REQUEST_ID_HEADER_NAME).stream().findFirst();
    headerExRequestId.ifPresent(
        value ->
            LOG.info(
                String.format(
                    "Unique Identifier associated with this request ( Received from Exhort Backend"
                        + " ) - ex-request-id= : %s",
                    value)));
  }

  public static boolean debugLoggingIsNeeded() {
    return Environment.getBoolean("TRUSTIFY_DA_DEBUG", false);
  }

  @Override
  public CompletableFuture<AnalysisReport> componentAnalysis(
      final String manifest, final byte[] manifestContent) throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    var manifestPath = Path.of(manifest);
    var provider = Ecosystem.getProvider(manifestPath);
    var uri = URI.create(String.format(S_API_V_5_ANALYSIS, getEndpoint()));
    var content = provider.provideComponent();
    commonHookAfterProviderCreatedSbomAndBeforeExhort();
    return getAnalysisReportForComponent(uri, content, exClientTraceId);
  }

  private void commonHookAfterProviderCreatedSbomAndBeforeExhort() {
    if (debugLoggingIsNeeded()) {
      LOG.info("After Provider created sbom hook");
      this.providerEndTime = LocalDateTime.now();
      LOG.info(String.format("After Creating Sbom time: %s", this.startTime));
      LOG.info(
          String.format(
              "Time took to create sbom file to be sent to exhort backend, in ms : %s, in seconds:"
                  + " %s",
              this.startTime.until(this.providerEndTime, ChronoUnit.MILLIS),
              this.startTime.until(this.providerEndTime, ChronoUnit.MILLIS) / 1000F));
    }
  }

  private void commonHookAfterExhortResponse() {
    if (debugLoggingIsNeeded()) {
      this.endTime = LocalDateTime.now();
      LOG.info(String.format("After got response from exhort time: %s", this.endTime));
      LOG.info(
          String.format(
              "Time took to get response from exhort backend, in ms: %s, in seconds: %s",
              this.providerEndTime.until(this.endTime, ChronoUnit.MILLIS),
              this.providerEndTime.until(this.endTime, ChronoUnit.MILLIS) / 1000F));
      LOG.info(
          String.format(
              "Total time took for complete analysis, in ms: %s, in seconds: %s",
              this.startTime.until(this.endTime, ChronoUnit.MILLIS),
              this.startTime.until(this.endTime, ChronoUnit.MILLIS) / 1000F));
    }
    RequestManager.getInstance().removeClientTraceIdFromRequest();
  }

  @Override
  public CompletableFuture<AnalysisReport> componentAnalysis(String manifestFile)
      throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    var manifestPath = Path.of(manifestFile);
    var provider = Ecosystem.getProvider(manifestPath);
    var uri = URI.create(String.format(S_API_V_5_ANALYSIS, getEndpoint()));
    var content = provider.provideComponent();
    commonHookAfterProviderCreatedSbomAndBeforeExhort();
    return getAnalysisReportForComponent(uri, content, exClientTraceId);
  }

  private CompletableFuture<AnalysisReport> getAnalysisReportForComponent(
      URI uri, Provider.Content content, String exClientTraceId) {
    return this.client
        .sendAsync(
            this.buildRequest(content, uri, MediaType.APPLICATION_JSON, "Component Analysis"),
            HttpResponse.BodyHandlers.ofString())
        //      .thenApply(HttpResponse::body)
        .thenApply(
            response ->
                getAnalysisReportFromResponse(
                    response, "Component Analysis", "json", exClientTraceId))
        .exceptionally(
            exception -> {
              LOG.severe(
                  String.format(
                      "failed to invoke Component Analysis for getting the json report, received"
                          + " message= %s ",
                      exception.getMessage()));
              //        LOG.log(System.Logger.Level.ERROR, "Exception Entity", exception);
              return new AnalysisReport();
            });
  }

  /**
   * Build an HTTP request wrapper for sending to the Backend API for Stack Analysis only.
   *
   * @param manifestFile the path for the manifest file
   * @param acceptType the type of requested content
   * @return a HttpRequest ready to be sent to the Backend API
   * @throws IOException when failed to load the manifest file
   */
  private HttpRequest buildStackRequest(final String manifestFile, final MediaType acceptType)
      throws IOException {
    var manifestPath = Path.of(manifestFile);
    var provider = Ecosystem.getProvider(manifestPath);
    var uri = URI.create(String.format(S_API_V_5_ANALYSIS, getEndpoint()));
    var content = provider.provideStack();
    commonHookAfterProviderCreatedSbomAndBeforeExhort();

    return buildRequest(content, uri, acceptType, "Stack Analysis");
  }

  @Override
  public String generateSbom(final String manifestFile) throws IOException {
    var manifestPath = Path.of(manifestFile);
    var provider = Ecosystem.getProvider(manifestPath);
    var content = provider.provideStack();
    return new String(content.buffer, java.nio.charset.StandardCharsets.UTF_8);
  }

  @Override
  public CompletableFuture<Map<ImageRef, AnalysisReport>> imageAnalysis(
      final Set<ImageRef> imageRefs) throws IOException {
    return this.performBatchAnalysis(
        () -> getBatchImageSboms(imageRefs),
        MediaType.APPLICATION_JSON,
        HttpResponse.BodyHandlers.ofString(),
        this::getBatchImageAnalysisReports,
        Collections::emptyMap,
        "Image Analysis");
  }

  @Override
  public CompletableFuture<byte[]> imageAnalysisHtml(Set<ImageRef> imageRefs) throws IOException {
    return this.performBatchAnalysis(
        () -> getBatchImageSboms(imageRefs),
        MediaType.TEXT_HTML,
        HttpResponse.BodyHandlers.ofByteArray(),
        HttpResponse::body,
        () -> new byte[0],
        "Image Analysis");
  }

  Map<String, JsonNode> getBatchImageSboms(final Set<ImageRef> imageRefs) {
    return imageRefs.parallelStream()
        .map(
            imageRef -> {
              try {
                return new AbstractMap.SimpleEntry<>(
                    imageRef.getPackageURL().canonicalize(),
                    ImageUtils.generateImageSBOM(imageRef));
              } catch (IOException | MalformedPackageURLException ex) {
                throw new RuntimeException(ex);
              }
            })
        .collect(
            Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));
  }

  Map<ImageRef, AnalysisReport> getBatchImageAnalysisReports(
      final HttpResponse<String> httpResponse) {
    if (httpResponse.statusCode() == 200) {
      try {
        Map<?, ?> reports = this.mapper.readValue(httpResponse.body(), Map.class);
        return reports.entrySet().stream()
            .collect(
                Collectors.toMap(
                    e -> {
                      try {
                        return new ImageRef(new PackageURL(e.getKey().toString()));
                      } catch (MalformedPackageURLException ex) {
                        throw new RuntimeException(ex);
                      }
                    },
                    e -> mapper.convertValue(e.getValue(), AnalysisReport.class)));
      } catch (JsonProcessingException e) {
        throw new CompletionException(e);
      }
    } else {
      return Collections.emptyMap();
    }
  }

  <H, T> CompletableFuture<T> performBatchAnalysis(
      final Supplier<Map<String, JsonNode>> sbomsGenerator,
      final MediaType mediaType,
      final HttpResponse.BodyHandler<H> responseBodyHandler,
      final Function<HttpResponse<H>, T> responseGenerator,
      final Supplier<T> exceptionResponseGenerator,
      final String analysisName)
      throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    var uri = URI.create(String.format(S_API_V_5_BATCH_ANALYSIS, getEndpoint()));
    var sboms = sbomsGenerator.get();
    var content =
        new Provider.Content(
            mapper.writeValueAsString(sboms).getBytes(StandardCharsets.UTF_8),
            Api.CYCLONEDX_MEDIA_TYPE);
    commonHookAfterProviderCreatedSbomAndBeforeExhort();
    return this.client
        .sendAsync(this.buildRequest(content, uri, mediaType, analysisName), responseBodyHandler)
        .thenApply(
            response ->
                getBatchAnalysisReportsFromResponse(
                    response, responseGenerator, analysisName, "json", exClientTraceId))
        .exceptionally(
            exception -> {
              LOG.severe(
                  String.format(
                      "failed to invoke %s for getting the json report, received message= %s ",
                      analysisName, exception.getMessage()));
              commonHookAfterExhortResponse();
              return exceptionResponseGenerator.get();
            });
  }

  <H, T> T getBatchAnalysisReportsFromResponse(
      final HttpResponse<H> response,
      final Function<HttpResponse<H>, T> responseGenerator,
      final String operation,
      final String reportName,
      final String exClientTraceId) {
    RequestManager.getInstance().addClientTraceIdToRequest(exClientTraceId);
    if (debugLoggingIsNeeded()) {
      logExhortRequestId(response);
    }
    if (response.statusCode() == 200) {
      if (debugLoggingIsNeeded()) {
        LOG.info(
            String.format(
                "Response body received from exhort server : %s %s",
                System.lineSeparator(), response.body()));
      }
    } else {
      LOG.severe(
          String.format(
              "failed to invoke %s for getting the %s report, Http Response Status=%s , "
                  + "received message from server= %s ",
              operation, reportName, response.statusCode(), response.body()));
    }
    commonHookAfterExhortResponse();
    return responseGenerator.apply(response);
  }

  private static boolean isLicenseCheckEnabled() {
    return Environment.getBoolean(TRUSTIFY_DA_LICENSE_CHECK, true);
  }

  @Override
  public CompletableFuture<ComponentAnalysisResult> componentAnalysisWithLicense(
      String manifestFile) throws IOException {
    String exClientTraceId = commonHookBeginning(false);
    var manifestPath = Path.of(manifestFile);
    var provider = Ecosystem.getProvider(manifestPath);
    var uri = URI.create(String.format(S_API_V_5_ANALYSIS, getEndpoint()));
    var content = provider.provideComponent();
    String sbomJson = new String(content.buffer);
    commonHookAfterProviderCreatedSbomAndBeforeExhort();
    return getAnalysisReportForComponent(uri, content, exClientTraceId)
        .thenCompose(
            report -> {
              if (!isLicenseCheckEnabled()) {
                return CompletableFuture.completedFuture(new ComponentAnalysisResult(report, null));
              }
              return LicenseCheck.runLicenseCheck(this, provider, manifestPath, sbomJson, report)
                  .thenApply(summary -> new ComponentAnalysisResult(report, summary))
                  .exceptionally(
                      ex -> {
                        LOG.warning(
                            String.format(
                                "License check failed, continuing without it: %s",
                                ex.getMessage()));
                        return new ComponentAnalysisResult(report, null);
                      });
            });
  }

  /**
   * Fetch license details by SPDX identifier from the backend GET /api/v5/licenses/{spdx}.
   *
   * @param spdxId SPDX identifier (e.g., "Apache-2.0", "MIT")
   * @return a CompletableFuture with license details as a JsonNode, or null if not found
   */
  public CompletableFuture<JsonNode> getLicenseDetails(String spdxId) {
    String encodedId = URLEncoder.encode(spdxId, StandardCharsets.UTF_8).replace("+", "%20");
    URI uri = URI.create(String.format(S_API_V5_LICENSES, getEndpoint(), encodedId));
    HttpRequest request = buildGetRequest(uri, "License Details");

    return this.client
        .sendAsync(request, HttpResponse.BodyHandlers.ofString())
        .thenApply(
            response -> {
              if (response.statusCode() == 200) {
                try {
                  return this.mapper.readTree(response.body());
                } catch (IOException e) {
                  LOG.warning(
                      String.format(
                          "Failed to parse license details for '%s': %s", spdxId, e.getMessage()));
                  return null;
                }
              }
              LOG.warning(
                  String.format(
                      "Failed to fetch license details for '%s': HTTP %d",
                      spdxId, response.statusCode()));
              return null;
            })
        .exceptionally(
            ex -> {
              LOG.warning(
                  String.format(
                      "Failed to fetch license details for '%s': %s", spdxId, ex.getMessage()));
              return null;
            });
  }

  /**
   * Call backend POST /api/v5/licenses/identify to identify license from file content.
   *
   * @param licenseFilePath path to LICENSE file
   * @return a CompletableFuture with SPDX identifier or null
   */
  public CompletableFuture<String> identifyLicense(Path licenseFilePath) {
    byte[] fileContent;
    try {
      fileContent = Files.readAllBytes(licenseFilePath);
    } catch (IOException e) {
      LOG.warning(String.format("Failed to read license file: %s", e.getMessage()));
      return CompletableFuture.completedFuture(null);
    }
    URI uri = URI.create(String.format(S_API_V5_LICENSES_IDENTIFY, getEndpoint()));
    HttpRequest request =
        buildPostRequest(
            uri,
            "application/octet-stream",
            HttpRequest.BodyPublishers.ofByteArray(fileContent),
            "License Identify");

    return this.client
        .sendAsync(request, HttpResponse.BodyHandlers.ofString())
        .thenApply(
            response -> {
              if (response.statusCode() == 200) {
                try {
                  JsonNode data = this.mapper.readTree(response.body());
                  JsonNode licenseNode = data.get("license");
                  if (licenseNode != null && licenseNode.has("id")) {
                    String id = licenseNode.get("id").asText();
                    return id.isBlank() ? null : id;
                  }
                  if (data.has("spdx_id")) {
                    String spdxId = data.get("spdx_id").asText();
                    return spdxId.isBlank() ? null : spdxId;
                  }
                  if (data.has("identifier")) {
                    String identifier = data.get("identifier").asText();
                    return identifier.isBlank() ? null : identifier;
                  }
                } catch (IOException e) {
                  LOG.warning(
                      String.format(
                          "Failed to parse license identify response: %s", e.getMessage()));
                }
              }
              return null;
            })
        .exceptionally(
            ex -> {
              LOG.warning(
                  String.format("Failed to identify license from file: %s", ex.getMessage()));
              return null;
            });
  }

  @Override
  public CompletableFuture<Map<String, AnalysisReport>> stackAnalysisBatch(
      final Path workspaceDir, final Set<String> ignorePatterns) throws IOException {
    return this.performBatchAnalysis(
        () -> getBatchStackSboms(workspaceDir, ignorePatterns),
        MediaType.APPLICATION_JSON,
        HttpResponse.BodyHandlers.ofString(),
        this::getBatchStackAnalysisReports,
        Collections::emptyMap,
        "Batch Stack Analysis");
  }

  @Override
  public CompletableFuture<byte[]> stackAnalysisBatchHtml(
      final Path workspaceDir, final Set<String> ignorePatterns) throws IOException {
    return this.performBatchAnalysis(
        () -> getBatchStackSboms(workspaceDir, ignorePatterns),
        MediaType.TEXT_HTML,
        HttpResponse.BodyHandlers.ofByteArray(),
        HttpResponse::body,
        () -> new byte[0],
        "Batch Stack Analysis");
  }

  Map<String, JsonNode> getBatchStackSboms(
      final Path workspaceDir, final Set<String> ignorePatterns) {
    boolean continueOnError = Environment.getBoolean("TRUSTIFY_DA_CONTINUE_ON_ERROR", true);
    int concurrency = resolveBatchConcurrency();
    try {
      Set<String> resolved = resolveIgnorePatterns(ignorePatterns);
      List<Path> manifests = discoverWorkspaceManifests(workspaceDir, resolved);
      if (manifests.isEmpty()) {
        LOG.warning("No workspace members discovered in " + workspaceDir);
        return Collections.emptyMap();
      }

      var executor = java.util.concurrent.Executors.newFixedThreadPool(concurrency);
      try {
        var futures =
            manifests.stream()
                .map(
                    manifest ->
                        java.util.concurrent.CompletableFuture.supplyAsync(
                            () -> {
                              try {
                                var provider = Ecosystem.getProvider(manifest);
                                var content = provider.provideStack();
                                var sbomJson = mapper.readTree(content.buffer);
                                var purl =
                                    sbomJson
                                        .at("/metadata/component/purl")
                                        .asText(
                                            sbomJson
                                                .at("/metadata/component/bom-ref")
                                                .asText(null));
                                if (purl == null || purl.isBlank()) {
                                  throw new IllegalStateException(
                                      "Missing purl in SBOM metadata.component for " + manifest);
                                }
                                return new AbstractMap.SimpleEntry<>(purl, sbomJson);
                              } catch (Exception ex) {
                                if (continueOnError) {
                                  LOG.warning(
                                      String.format(
                                          "Skipping manifest %s due to error: %s",
                                          manifest, ex.getMessage()));
                                  return null;
                                }
                                throw new RuntimeException(
                                    "Failed to generate SBOM for " + manifest, ex);
                              }
                            },
                            executor))
                .toList();

        var results =
            futures.stream()
                .map(java.util.concurrent.CompletableFuture::join)
                .filter(Objects::nonNull)
                .collect(
                    Collectors.toMap(
                        AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

        if (Environment.getBoolean("TRUSTIFY_DA_BATCH_METADATA", false)) {
          int failed = manifests.size() - results.size();
          LOG.info(
              String.format(
                  "Batch metadata: workspaceRoot=%s, total=%d, successful=%d, failed=%d",
                  workspaceDir, manifests.size(), results.size(), failed));
        }

        return results;
      } finally {
        executor.shutdown();
      }
    } catch (IOException e) {
      throw new RuntimeException("Failed to discover workspace manifests", e);
    }
  }

  Map<String, AnalysisReport> getBatchStackAnalysisReports(
      final HttpResponse<String> httpResponse) {
    if (httpResponse.statusCode() == 200) {
      try {
        Map<?, ?> reports = this.mapper.readValue(httpResponse.body(), Map.class);
        return reports.entrySet().stream()
            .collect(
                Collectors.toMap(
                    e -> e.getKey().toString(),
                    e -> mapper.convertValue(e.getValue(), AnalysisReport.class)));
      } catch (JsonProcessingException e) {
        throw new CompletionException(e);
      }
    } else {
      return Collections.emptyMap();
    }
  }

  /** Resolves batch concurrency from TRUSTIFY_DA_BATCH_CONCURRENCY. default 10, max 256. */
  int resolveBatchConcurrency() {
    String raw = Environment.get("TRUSTIFY_DA_BATCH_CONCURRENCY", "10");
    try {
      int n = Integer.parseInt(raw.trim());
      if (n < 1) {
        return 10;
      }
      return Math.min(256, n);
    } catch (NumberFormatException e) {
      return 10;
    }
  }

  private static final Set<String> DEFAULT_WORKSPACE_DISCOVERY_IGNORE =
      Set.of(
          "**/node_modules/**",
          "**/.git/**",
          "**/target/**",
          "**/build/**",
          "**/.gradle/**",
          "**/__pycache__/**",
          "**/.venv/**");

  /** Merges default ignore patterns, env var overrides, and caller-provided patterns. */
  Set<String> resolveIgnorePatterns(Set<String> callerPatterns) {
    var merged = new java.util.LinkedHashSet<>(DEFAULT_WORKSPACE_DISCOVERY_IGNORE);
    String fromEnv = Environment.get("TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE", null);
    if (fromEnv != null && !fromEnv.isBlank()) {
      for (String p : fromEnv.split(",")) {
        String trimmed = p.trim();
        if (!trimmed.isEmpty()) {
          merged.add(trimmed);
        }
      }
    }
    if (callerPatterns != null) {
      merged.addAll(callerPatterns);
    }
    return merged;
  }

  /**
   * Detects the workspace ecosystem and discovers manifest paths. Checks for Cargo workspace first
   * (Cargo.toml + Cargo.lock), then falls back to JS workspace discovery.
   */
  List<Path> discoverWorkspaceManifests(Path workspaceDir, Set<String> ignorePatterns)
      throws IOException {
    // Cargo workspace: Cargo.toml + Cargo.lock
    Path cargoToml = workspaceDir.resolve("Cargo.toml");
    Path cargoLock = workspaceDir.resolve("Cargo.lock");
    if (Files.isRegularFile(cargoToml) && Files.isRegularFile(cargoLock)) {
      return discoverCargoManifests(workspaceDir, ignorePatterns);
    }

    // Gradle multi-project: settings.gradle or settings.gradle.kts
    boolean hasGradleSettings =
        Files.isRegularFile(workspaceDir.resolve("settings.gradle"))
            || Files.isRegularFile(workspaceDir.resolve("settings.gradle.kts"));
    if (hasGradleSettings) {
      return discoverGradleSubprojects(workspaceDir, ignorePatterns);
    }

    // Go workspace: go.work
    if (Files.isRegularFile(workspaceDir.resolve("go.work"))) {
      List<Path> goManifests = discoverGoWorkspaceModules(workspaceDir, ignorePatterns);
      if (!goManifests.isEmpty()) {
        return goManifests;
      }
    }

    // uv workspace: pyproject.toml with [tool.uv.workspace] + uv.lock
    if (Files.isRegularFile(workspaceDir.resolve("pyproject.toml"))
        && Files.isRegularFile(workspaceDir.resolve("uv.lock"))) {
      List<Path> uvManifests = discoverUvWorkspaceMembers(workspaceDir, ignorePatterns);
      if (!uvManifests.isEmpty()) {
        return uvManifests;
      }
    }

    // JS workspace: require package.json + a lock file
    Path packageJson = workspaceDir.resolve("package.json");
    boolean hasJsLock =
        Files.isRegularFile(workspaceDir.resolve("pnpm-lock.yaml"))
            || Files.isRegularFile(workspaceDir.resolve("yarn.lock"))
            || Files.isRegularFile(workspaceDir.resolve("package-lock.json"));

    if (Files.isRegularFile(packageJson) && hasJsLock) {
      List<Path> manifests =
          JsWorkspaceDiscovery.discoverWorkspaceManifests(workspaceDir, ignorePatterns);
      if (manifests.isEmpty()) {
        return List.of(packageJson);
      }
      // Include root package.json if it is not private and not already discovered
      if (!manifests.contains(packageJson) && !isPrivatePackageJson(packageJson)) {
        var withRoot = new ArrayList<>(manifests);
        withRoot.addFirst(packageJson);
        manifests = withRoot;
      }
      return manifests;
    }

    return Collections.emptyList();
  }

  private List<Path> discoverCargoManifests(Path workspaceDir, Set<String> ignorePatterns) {
    try {
      String cargo = Operations.getCustomPathOrElse("cargo");
      Operations.ProcessExecOutput output =
          Operations.runProcessGetFullOutput(
              workspaceDir,
              new String[] {cargo, "metadata", "--format-version", "1", "--no-deps"},
              null);
      if (output.getExitCode() != 0) {
        LOG.warning("cargo metadata failed with exit code " + output.getExitCode());
        return Collections.emptyList();
      }
      CargoMetadata metadata = mapper.readValue(output.getOutput(), CargoMetadata.class);
      var memberIds = new java.util.HashSet<String>(metadata.workspaceMembers());
      List<Path> manifests = new ArrayList<>();
      for (var pkg : metadata.packages()) {
        if (memberIds.contains(pkg.id()) && pkg.manifestPath() != null) {
          Path manifestPath = Path.of(pkg.manifestPath());
          if (Files.isRegularFile(manifestPath)) {
            manifests.add(manifestPath);
          }
        }
      }
      return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifests, ignorePatterns);
    } catch (Exception e) {
      LOG.warning("Failed to discover Cargo workspace manifests: " + e.getMessage());
      return Collections.emptyList();
    }
  }

  /**
   * Discover all go.mod manifest paths in a Go workspace. Uses {@code go work edit -json} to get
   * workspace members.
   */
  private List<Path> discoverGoWorkspaceModules(Path workspaceDir, Set<String> ignorePatterns) {
    try {
      String goBin = Operations.getCustomPathOrElse("go");
      Path goWork = workspaceDir.resolve("go.work");
      Operations.ProcessExecOutput output =
          Operations.runProcessGetFullOutput(
              workspaceDir, new String[] {goBin, "work", "edit", "-json", goWork.toString()}, null);
      if (output.getExitCode() != 0) {
        LOG.warning("go work edit -json failed with exit code " + output.getExitCode());
        return Collections.emptyList();
      }
      GoWorkspace workspace = mapper.readValue(output.getOutput(), GoWorkspace.class);
      if (workspace.use() == null || workspace.use().isEmpty()) {
        return Collections.emptyList();
      }
      List<Path> manifests = new ArrayList<>();
      for (var entry : workspace.use()) {
        if (entry.diskPath() == null || entry.diskPath().isBlank()) {
          continue;
        }
        Path moduleDir = workspaceDir.resolve(entry.diskPath()).normalize();
        Path goMod = moduleDir.resolve("go.mod");
        if (Files.isRegularFile(goMod)) {
          manifests.add(goMod);
        }
      }
      return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifests, ignorePatterns);
    } catch (Exception e) {
      LOG.warning("Failed to discover Go workspace modules: " + e.getMessage());
      return Collections.emptyList();
    }
  }

  /**
   * Discover all pyproject.toml manifest paths in a uv workspace. Parses the root pyproject.toml
   * for {@code [tool.uv.workspace]} member and exclude globs, then walks the filesystem to find
   * matching member directories.
   */
  private List<Path> discoverUvWorkspaceMembers(Path workspaceDir, Set<String> ignorePatterns) {
    try {
      Path rootPyproject = workspaceDir.resolve("pyproject.toml");
      TomlParseResult toml = PyprojectTomlUtils.parseToml(rootPyproject);

      TomlTable workspaceConfig = toml.getTable("tool.uv.workspace");
      if (workspaceConfig == null) {
        return Collections.emptyList();
      }

      TomlArray membersArray = workspaceConfig.getArray("members");
      if (membersArray == null || membersArray.isEmpty()) {
        return Collections.emptyList();
      }

      List<String> memberPatterns = new ArrayList<>();
      for (int i = 0; i < membersArray.size(); i++) {
        String pattern = membersArray.getString(i);
        if (pattern != null && !pattern.isBlank()) {
          memberPatterns.add(pattern.trim());
        }
      }
      if (memberPatterns.isEmpty()) {
        return Collections.emptyList();
      }

      Set<String> excludePatterns = new java.util.HashSet<>();
      TomlArray excludeArray = workspaceConfig.getArray("exclude");
      if (excludeArray != null) {
        for (int i = 0; i < excludeArray.size(); i++) {
          String pattern = excludeArray.getString(i);
          if (pattern != null && !pattern.isBlank()) {
            excludePatterns.add(pattern.trim());
          }
        }
      }

      List<PathMatcher> memberMatchers =
          memberPatterns.stream()
              .map(p -> FileSystems.getDefault().getPathMatcher("glob:" + p))
              .toList();

      List<PathMatcher> excludeMatchers =
          excludePatterns.stream()
              .map(p -> FileSystems.getDefault().getPathMatcher("glob:" + p))
              .toList();

      List<Path> manifests = new ArrayList<>();
      try (var stream = Files.walk(workspaceDir)) {
        stream
            .filter(p -> p.getFileName().toString().equals("pyproject.toml"))
            .filter(p -> !p.equals(rootPyproject))
            .forEach(
                p -> {
                  Path relative = workspaceDir.relativize(p.getParent());
                  boolean matchesMember =
                      memberMatchers.stream().anyMatch(m -> m.matches(relative));
                  boolean matchesExclude =
                      excludeMatchers.stream().anyMatch(m -> m.matches(relative));
                  if (matchesMember && !matchesExclude) {
                    manifests.add(p);
                  }
                });
      }

      if (PyprojectTomlUtils.getProjectName(toml) != null) {
        manifests.addFirst(rootPyproject);
      }

      return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifests, ignorePatterns);
    } catch (Exception e) {
      LOG.warning("Failed to discover uv workspace members: " + e.getMessage());
      return Collections.emptyList();
    }
  }

  private static final String GRADLE_INIT_SCRIPT =
      "allprojects {\n"
          + "    task daListProjects {\n"
          + "        doLast {\n"
          + "            println \"::DA_PROJECT::${project.path}::${project.projectDir}\"\n"
          + "        }\n"
          + "    }\n"
          + "}\n";

  /**
   * Resolve the Gradle binary, preferring gradlew wrapper when available and configured.
   *
   * @param startDir directory from which to start the wrapper search
   * @return path to the Gradle binary
   */
  private static String resolveGradleBinary(Path startDir) {
    if (Operations.getWrapperPreference("gradle")) {
      String wrapperName = Operations.isWindows() ? "gradlew.bat" : "gradlew";
      String wrapper =
          JavaMavenProvider.traverseForMvnw(
              wrapperName, startDir.resolve("build.gradle").toString());
      if (wrapper != null) {
        return wrapper;
      }
    }
    return Operations.getCustomPathOrElse("gradle");
  }

  /**
   * Discover all build.gradle[.kts] manifest paths in a Gradle multi-project build. Uses a custom
   * init script to get a structured project listing.
   */
  private List<Path> discoverGradleSubprojects(Path workspaceDir, Set<String> ignorePatterns) {
    Path rootBuildKts = workspaceDir.resolve("build.gradle.kts");
    Path rootBuild = workspaceDir.resolve("build.gradle");

    List<Path> manifestPaths = new ArrayList<>();
    if (Files.isRegularFile(rootBuildKts)) {
      manifestPaths.add(rootBuildKts);
    } else if (Files.isRegularFile(rootBuild)) {
      manifestPaths.add(rootBuild);
    }

    String gradleBin = resolveGradleBinary(workspaceDir);
    Path initScriptPath = null;
    try {
      initScriptPath = Files.createTempFile("da-list-projects-", ".gradle");
      Files.writeString(initScriptPath, GRADLE_INIT_SCRIPT);

      Operations.ProcessExecOutput output =
          Operations.runProcessGetFullOutput(
              workspaceDir,
              new String[] {
                gradleBin,
                "-q",
                "--no-daemon",
                "--init-script",
                initScriptPath.toString(),
                "daListProjects"
              },
              null);

      if (output.getExitCode() != 0) {
        LOG.warning("gradle daListProjects failed with exit code " + output.getExitCode());
        return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifestPaths, ignorePatterns);
      }

      for (var proj : parseGradleInitScriptOutput(output.getOutput())) {
        if (":".equals(proj.path())) {
          continue;
        }
        Path projDir = Path.of(proj.dir()).toAbsolutePath().normalize();
        Path buildKts = projDir.resolve("build.gradle.kts");
        Path buildGroovy = projDir.resolve("build.gradle");
        if (Files.isRegularFile(buildKts)) {
          manifestPaths.add(buildKts);
        } else if (Files.isRegularFile(buildGroovy)) {
          manifestPaths.add(buildGroovy);
        }
      }
    } catch (Exception e) {
      LOG.warning("Failed to discover Gradle subprojects: " + e.getMessage());
      return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifestPaths, ignorePatterns);
    } finally {
      if (initScriptPath != null) {
        try {
          Files.deleteIfExists(initScriptPath);
        } catch (IOException ignored) {
        }
      }
    }

    return WorkspaceUtils.filterByIgnorePatterns(workspaceDir, manifestPaths, ignorePatterns);
  }

  record GradleProject(String path, String dir) {}

  static List<GradleProject> parseGradleInitScriptOutput(String raw) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    List<GradleProject> projects = new ArrayList<>();
    for (String line : raw.split("\n")) {
      if (!line.startsWith("::DA_PROJECT::")) {
        continue;
      }
      String[] parts = line.split("::");
      List<String> nonEmpty = new ArrayList<>();
      for (String part : parts) {
        if (!part.isEmpty()) {
          nonEmpty.add(part);
        }
      }
      if (nonEmpty.size() >= 3) {
        projects.add(new GradleProject(nonEmpty.get(1), nonEmpty.get(2)));
      }
    }
    return projects;
  }

  /**
   * Checks whether a package.json has "private": true, meaning it should not be analyzed as a
   * publishable package.
   */
  private boolean isPrivatePackageJson(Path packageJson) {
    try {
      JsonNode root = mapper.readTree(Files.newInputStream(packageJson));
      JsonNode privateField = root.get("private");
      return privateField != null && privateField.asBoolean(false);
    } catch (IOException e) {
      LOG.warning("Failed to read " + packageJson + ": " + e.getMessage());
      return true;
    }
  }

  /**
   * Build an HTTP request for sending to the Backend API.
   *
   * @param content the {@link io.github.guacsec.trustifyda.Provider.Content} info for the request
   *     body
   * @param uri the {@link URI} for sending the request to
   * @param acceptType value the Accept header in the request, indicating the required response type
   * @return a HttpRequest ready to be sent to the Backend API
   */
  private HttpRequest buildRequest(
      final Provider.Content content,
      final URI uri,
      final MediaType acceptType,
      final String analysisType) {
    var request =
        HttpRequest.newBuilder(uri)
            .version(Version.HTTP_1_1)
            .setHeader("Accept", acceptType.toString())
            .setHeader("Content-Type", content.type)
            .POST(HttpRequest.BodyPublishers.ofString(new String(content.buffer)));

    applyCommonHeaders(request, analysisType);

    return request.build();
  }

  private HttpRequest buildGetRequest(final URI uri, final String operationType) {
    var request =
        HttpRequest.newBuilder(uri)
            .version(Version.HTTP_1_1)
            .setHeader("Accept", MediaType.APPLICATION_JSON.toString())
            .GET();

    applyCommonHeaders(request, operationType);

    return request.build();
  }

  private HttpRequest buildPostRequest(
      final URI uri,
      final String contentType,
      final HttpRequest.BodyPublisher bodyPublisher,
      final String operationType) {
    var request =
        HttpRequest.newBuilder(uri)
            .version(Version.HTTP_1_1)
            .setHeader("Accept", MediaType.APPLICATION_JSON.toString())
            .setHeader("Content-Type", contentType)
            .POST(bodyPublisher);

    applyCommonHeaders(request, operationType);

    return request.build();
  }

  private void applyCommonHeaders(HttpRequest.Builder request, String operationType) {
    String trustDaToken = calculateHeaderValue(TRUST_DA_TOKEN_HEADER);
    if (trustDaToken != null) {
      request.setHeader(TRUST_DA_TOKEN_HEADER, trustDaToken);
    }
    String trustDaSource = calculateHeaderValue(TRUST_DA_SOURCE_HEADER);
    if (trustDaSource != null) {
      request.setHeader(TRUST_DA_SOURCE_HEADER, trustDaSource);
    }
    request.setHeader(TRUST_DA_OPERATION_TYPE_HEADER, operationType);
  }

  private String calculateHeaderValue(String headerName) {
    String result;
    result = calculateHeaderValueActual(headerName);
    if (result == null) {
      result = calculateHeaderValueActual(headerName.toUpperCase().replace("-", "_"));
    }
    return result;
  }

  private String calculateHeaderValueActual(String headerName) {
    return Environment.get(headerName);
  }
}
