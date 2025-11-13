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
import com.redhat.exhort.api.v4.AnalysisReport;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.Provider;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.image.ImageUtils;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.utils.Environment;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/** Concrete implementation of the Exhort {@link Api} Service. */
public final class ExhortApi implements Api {

  private static final String DEV_TRUSTIFY_DA_BACKEND_URL = "DEV_TRUSTIFY_DA_BACKEND_URL";

  private static final String TRUSTIFY_DA_DEV_MODE = "TRUSTIFY_DA_DEV_MODE";

  private static final String HTTP_VERSION_TRUSTIFY_DA_CLIENT = "HTTP_VERSION_TRUSTIFY_DA_CLIENT";

  private static final String TRUSTIFY_DA_PROXY_URL = "TRUSTIFY_DA_PROXY_URL";

  private static final Logger LOG = LoggersFactory.getLogger(ExhortApi.class.getName());

  public static final String DEFAULT_ENDPOINT = "https://rhda.rhcloud.com";
  public static final String DEFAULT_ENDPOINT_DEV = "https://exhort.stage.devshift.net";
  public static final String TRUST_DA_TOKEN_HEADER = "trust-da-token";
  public static final String TRUST_DA_SOURCE_HEADER = "trust-da-source";
  public static final String TRUST_DA_OPERATION_TYPE_HEADER = "trust-da-operation-type";
  public static final String TRUSTIFY_DA_REQUEST_ID_HEADER_NAME = "ex-request-id";

  private final String endpoint;

  public String getEndpoint() {
    return endpoint;
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
    //    // temp system property - as long as prod exhort url not implemented the multi-source v4
    // endpoint, this
    // property needs to be true
    //    System.setProperty("TRUSTIFY_DA_DEV_MODE","true");
    commonHookBeginning(true);
    this.client = client;
    this.mapper = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    // Take default from config.properties in case client didn't override DEV MODE
    if (Environment.get(TRUSTIFY_DA_DEV_MODE) == null) {
      try {
        InputStream exhortConfig =
            this.getClass().getClassLoader().getResourceAsStream("config.properties");
        if (exhortConfig == null) {
          LOG.info(
              "config.properties not found on the class path, fallback to default DEV MODE ="
                  + " false");
          System.setProperty(TRUSTIFY_DA_DEV_MODE, "false");
        } else {
          Properties properties = new Properties();
          properties.load(exhortConfig);
          System.setProperty(TRUSTIFY_DA_DEV_MODE, (String) properties.get(TRUSTIFY_DA_DEV_MODE));
        }
      } catch (IOException e) {
        LOG.info(
            String.format(
                "Error loading config.properties , fallback to set default property DEV MODE ="
                    + " false, Error message = %s",
                e.getMessage()));
        System.setProperty(TRUSTIFY_DA_DEV_MODE, "false");
      }
    }

    this.endpoint = getExhortUrl();
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

  public String getExhortUrl() {
    String endpoint;
    if (Environment.getBoolean(TRUSTIFY_DA_DEV_MODE, false)) {
      endpoint = Environment.get(DEV_TRUSTIFY_DA_BACKEND_URL, DEFAULT_ENDPOINT_DEV);

    } else {
      endpoint = DEFAULT_ENDPOINT;
    }
    if (debugLoggingIsNeeded()) {
      LOG.info(
          String.format(
              "TRUSTIFY_DA_DEV_MODE=%s,DEV_TRUSTIFY_DA_BACKEND_URL=%s, Chosen Backend URL=%s ,"
                  + " DEFAULT_ENDPOINT_DEV=%s , DEFAULT_ENDPOINT=%s",
              Environment.getBoolean(TRUSTIFY_DA_DEV_MODE, false),
              Environment.get(DEV_TRUSTIFY_DA_BACKEND_URL, DEFAULT_ENDPOINT_DEV),
              endpoint,
              DEFAULT_ENDPOINT_DEV,
              DEFAULT_ENDPOINT));
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
        //      .thenApply(HttpResponse::body)
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
              //        LOG.log(System.Logger.Level.ERROR, "Exception Entity", exception);
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
    var uri = URI.create(String.format("%s/api/v4/analysis", this.endpoint));
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
    var uri = URI.create(String.format("%s/api/v4/analysis", this.endpoint));
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
    var uri = URI.create(String.format("%s/api/v4/analysis", this.endpoint));
    var content = provider.provideStack();
    commonHookAfterProviderCreatedSbomAndBeforeExhort();

    return buildRequest(content, uri, acceptType, "Stack Analysis");
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
    var uri = URI.create(String.format("%s/api/v4/batch-analysis", this.endpoint));
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

    // set trust-da-token
    // Environment variable/property name = TRUST_DA_TOKEN
    String trustDaToken = calculateHeaderValue(TRUST_DA_TOKEN_HEADER);
    if (trustDaToken != null) {
      request.setHeader(TRUST_DA_TOKEN_HEADER, trustDaToken);
    }
    // set trust-da-source ( extension/plugin id/name)
    // Environment variable/property name = TRUST_DA_SOURCE
    String trustDaSource = calculateHeaderValue(TRUST_DA_SOURCE_HEADER);
    if (trustDaSource != null) {
      request.setHeader(TRUST_DA_SOURCE_HEADER, trustDaSource);
    }
    request.setHeader(TRUST_DA_OPERATION_TYPE_HEADER, analysisType);

    return request.build();
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
