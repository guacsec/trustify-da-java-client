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

import static io.github.guacsec.trustifyda.Provider.PROP_MATCH_MANIFEST_VERSIONS;
import static io.github.guacsec.trustifyda.image.ImageUtils.SKIP_VALIDATION_KEY;
import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS;
import static io.github.guacsec.trustifyda.utils.PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mockStatic;

import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.ExhortTest;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.providers.HelperExtension;
import io.github.guacsec.trustifyda.providers.JavaScriptNpmProvider;
import io.github.guacsec.trustifyda.providers.JavaScriptPnpmProvider;
import io.github.guacsec.trustifyda.providers.JavaScriptYarnProvider;
import io.github.guacsec.trustifyda.tools.Ecosystem;
import io.github.guacsec.trustifyda.tools.Operations;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.junitpioneer.jupiter.SetSystemProperty;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

@Tag("IntegrationTest")
@ExtendWith(HelperExtension.class)
@ExtendWith(MockitoExtension.class)
@SetSystemProperty(key = "TRUSTIFY_DA_BACKEND_URL", value = "https://exhort.stage.devshift.net")
@SetSystemProperty(key = "TRUST_DA_SOURCE", value = "trustify-da-java-client-it")
@RestoreSystemProperties
class ExhortApiIT extends ExhortTest {

  private static Api api;
  private static Map<String, AbstractMap.SimpleEntry<String, Optional<String>>>
      ecoSystemsManifestNames;

  private MockedStatic<Operations> mockedOperations;

  @BeforeAll
  static void beforeAll() {
    api = new ExhortApi();
    ecoSystemsManifestNames =
        Map.of(
            "golang",
            new SimpleEntry<>("go.mod", Optional.empty()),
            "maven",
            new SimpleEntry<>("pom.xml", Optional.empty()),
            "npm",
            new SimpleEntry<>("package.json", Optional.of(JavaScriptNpmProvider.LOCK_FILE)),
            "pnpm",
            new SimpleEntry<>("package.json", Optional.of(JavaScriptPnpmProvider.LOCK_FILE)),
            "yarn",
            new SimpleEntry<>("package.json", Optional.of(JavaScriptYarnProvider.LOCK_FILE)),
            "pypi",
            new SimpleEntry<>("requirements.txt", Optional.empty()),
            "gradle-groovy",
            new SimpleEntry<>("build.gradle", Optional.empty()),
            "gradle-kotlin",
            new SimpleEntry<>("build.gradle.kts", Optional.empty()));
  }

  private static List<Arguments> scenarios() {
    return ecoSystemsManifestNames.entrySet().stream()
        .map(e -> Arguments.of(e.getKey(), e.getValue().getKey(), e.getValue().getValue()))
        .collect(Collectors.toList());
  }

  @Tag("IntegrationTest")
  @ParameterizedTest(name = "StackAnalysis for: {0} with manifest: {1}")
  @MethodSource("scenarios")
  @RestoreSystemProperties
  void Integration_Test_End_To_End_Stack_Analysis(
      String useCase, String manifestFileName, Optional<String> lockFilename)
      throws IOException, ExecutionException, InterruptedException {
    Path manifestDirPath =
        new TempDirFromResources()
            .addFile(manifestFileName)
            .fromResources(String.format("tst_manifests/it/%s/%s", useCase, manifestFileName))
            .addFile(
                lockFilename,
                () -> String.format("tst_manifests/it/%s/%s", useCase, lockFilename.get()))
            .getTempDir();
    Path manifestFileNamePath = manifestDirPath.resolve(manifestFileName);
    var provider = Ecosystem.getProvider(manifestFileNamePath);
    var packageManager = provider.ecosystem;
    preparePythonEnvironment(packageManager);
    // Github action runner with all maven and java versions seems to enter infinite loop in
    // integration tests of
    // MAVEN when running dependency maven plugin to produce verbose text dependenct tree format.
    // locally it's not recreated with same versions
    mockMavenDependencyTree(packageManager);
    AnalysisReport analysisReportResult = api.stackAnalysis(manifestFileNamePath.toString()).get();
    handleJsonResponse(analysisReportResult, true);
    releaseStaticMock(packageManager);
  }

  private void releaseStaticMock(Ecosystem.Type packageManager) {
    if (packageManager.equals(Ecosystem.Type.MAVEN)) {
      this.mockedOperations.close();
    }
  }

  @Tag("IntegrationTest")
  @ParameterizedTest(name = "StackAnalysis Mixed for: {0} with manifest: {1}")
  @MethodSource("scenarios")
  @RestoreSystemProperties
  void Integration_Test_End_To_End_Stack_Analysis_Mixed(
      String useCase, String manifestFileName, Optional<String> lockFilename)
      throws IOException, ExecutionException, InterruptedException {
    Path manifestDirPath =
        new TempDirFromResources()
            .addFile(manifestFileName)
            .fromResources(String.format("tst_manifests/it/%s/%s", useCase, manifestFileName))
            .addFile(
                lockFilename,
                () -> String.format("tst_manifests/it/%s/%s", useCase, lockFilename.get()))
            .getTempDir();
    Path manifestFileNamePath = manifestDirPath.resolve(manifestFileName);
    String pathToManifest = manifestFileNamePath.toString();
    var provider = Ecosystem.getProvider(Path.of(pathToManifest));
    var packageManager = provider.ecosystem;
    preparePythonEnvironment(packageManager);
    // Github action runner with all maven and java versions seems to enter infinite loop in
    // integration tests of
    // MAVEN when runnig dependency maven plugin to produce verbose text dependenct tree format.
    // locally it's not recreated with same versions
    mockMavenDependencyTree(packageManager);
    AnalysisReport analysisReportJson = api.stackAnalysisMixed(pathToManifest).get().json;
    String analysisReportHtml = new String(api.stackAnalysisMixed(pathToManifest).get().html);
    handleJsonResponse(analysisReportJson, true);
    handleHtmlResponse(analysisReportHtml);
    releaseStaticMock(packageManager);
  }

  @Tag("IntegrationTest")
  @ParameterizedTest(name = "StackAnalysis HTML for: {0} with manifest: {1}")
  @MethodSource("scenarios")
  @RestoreSystemProperties
  void Integration_Test_End_To_End_Stack_Analysis_Html(
      String useCase, String manifestFileName, Optional<String> lockFilename)
      throws IOException, ExecutionException, InterruptedException {
    Path manifestDirPath =
        new TempDirFromResources()
            .addFile(manifestFileName)
            .fromResources(String.format("tst_manifests/it/%s/%s", useCase, manifestFileName))
            .addFile(
                lockFilename,
                () -> String.format("tst_manifests/it/%s/%s", useCase, lockFilename.get()))
            .getTempDir();
    Path manifestFileNamePath = manifestDirPath.resolve(manifestFileName);
    String pathToManifest = manifestFileNamePath.toString();
    var provider = Ecosystem.getProvider(Path.of(pathToManifest));
    var packageManager = provider.ecosystem;
    preparePythonEnvironment(packageManager);
    // Github action runner with all maven and java versions seems to enter infinite loop in
    // integration tests of
    // MAVEN when running dependency maven plugin to produce verbose text dependenct tree format.
    // locally it's not recreated with same versions
    mockMavenDependencyTree(packageManager);
    String analysisReportHtml = new String(api.stackAnalysisHtml(pathToManifest).get());
    releaseStaticMock(packageManager);
    handleHtmlResponse(analysisReportHtml);
  }

  @Tag("IntegrationTest")
  @ParameterizedTest
  @RestoreSystemProperties
  @EnumSource(
      value = Ecosystem.Type.class,
      names = {"GOLANG", "MAVEN", "NPM", "PNPM", "YARN", "PYTHON"})
  void Integration_Test_End_To_End_Component_Analysis(Ecosystem.Type packageManager)
      throws IOException, ExecutionException, InterruptedException {
    String manifestFileName = ecoSystemsManifestNames.get(packageManager.getType()).getKey();

    Path tempDir =
        new TempDirFromResources()
            .addDirectory(
                packageManager.getType(),
                String.format("tst_manifests/it/%s", packageManager.getType()))
            .getTempDir();
    Path manifestPath = tempDir.resolve(packageManager.getType()).resolve(manifestFileName);
    byte[] manifestContent = Files.readAllBytes(manifestPath);

    preparePythonEnvironment(packageManager);
    AnalysisReport analysisReportResult =
        api.componentAnalysis(manifestPath.toString(), manifestContent).get();
    handleJsonResponse(analysisReportResult, false);
  }

  @Tag("IntegrationTest")
  @Test
  @SetSystemProperty(key = SKIP_VALIDATION_KEY, value = "true")
  void Integration_Test_End_To_End_Image_Analysis() throws IOException {
    var result =
        testImageAnalysis(
            i -> {
              try {
                return api.imageAnalysis(i).get();
              } catch (InterruptedException | ExecutionException | IOException e) {
                throw new RuntimeException(e);
              }
            });

    assertEquals(1, result.size());
    handleJsonResponse(new ArrayList<>(result.values()).get(0), false);
  }

  @Tag("IntegrationTest")
  @Test
  @SetSystemProperty(key = SKIP_VALIDATION_KEY, value = "true")
  void Integration_Test_End_To_End_Image_Analysis_Html() throws IOException {
    var result =
        testImageAnalysis(
            i -> {
              try {
                return api.imageAnalysisHtml(i).get();
              } catch (InterruptedException | ExecutionException | IOException e) {
                throw new RuntimeException(e);
              }
            });

    handleHtmlResponseForImage(new String(result));
  }

  private static <T> T testImageAnalysis(Function<Set<ImageRef>, T> imageAnalysisFunction)
      throws IOException {
    try (MockedStatic<Operations> mock = Mockito.mockStatic(Operations.class);
        var sbomIS = getResourceAsStreamDecision(ExhortApiIT.class, "msc/image/image_sbom.json")) {

      var imageRef =
          new ImageRef(
              "test.io/test/test-app:test-version@sha256:1fafb0905264413501df60d90a92ca32df8a2011cbfb4876ddff5ceb20c8f165",
              "linux/amd64");

      var jsonSbom =
          new BufferedReader(new InputStreamReader(sbomIS, StandardCharsets.UTF_8))
              .lines()
              .collect(Collectors.joining("\n"));
      var output = new Operations.ProcessExecOutput(jsonSbom, "", 0);

      mock.when(() -> Operations.getCustomPathOrElse(eq("syft"))).thenReturn("syft");

      mock.when(() -> Operations.getExecutable(eq("syft"), any())).thenReturn("syft");

      mock.when(
              () ->
                  Operations.runProcessGetFullOutput(
                      isNull(),
                      aryEq(
                          new String[] {
                            "syft",
                            imageRef.getImage().getFullName(),
                            "-s",
                            "all-layers",
                            "-o",
                            "cyclonedx-json",
                            "-q"
                          }),
                      isNull()))
          .thenReturn(output);

      return imageAnalysisFunction.apply(Set.of(imageRef));
    }
  }

  private static void preparePythonEnvironment(Ecosystem.Type packageManager) {
    if (packageManager.equals(Ecosystem.Type.PYTHON)) {
      System.setProperty(PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV, "true");
      System.setProperty(PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS, "true");
      System.setProperty(PROP_MATCH_MANIFEST_VERSIONS, "false");
    }
  }

  private static void handleJsonResponse(
      AnalysisReport analysisReportResult, boolean positiveNumberOfTransitives) {
    analysisReportResult.getProviders().entrySet().stream()
        .forEach(
            provider -> {
              assertTrue(provider.getValue().getStatus().getOk());
              assertThat(provider.getValue().getStatus().getCode())
                  .isEqualTo(HttpURLConnection.HTTP_OK);
            });
    analysisReportResult.getProviders().values().stream()
        .map(ProviderReport::getSources)
        .map(Map::entrySet)
        .flatMap(Collection::stream)
        .map(Map.Entry::getValue)
        .forEach(source -> assertThat(source.getSummary().getTotal()).isGreaterThan(0));

    if (positiveNumberOfTransitives) {
      assertThat(analysisReportResult.getScanned().getTransitive()).isGreaterThan(0);
    } else {
      assertThat(analysisReportResult.getScanned().getTransitive()).isZero();
    }
  }

  private void handleHtmlResponse(String analysisReportHtml) {
    assertThat(analysisReportHtml).contains("svg", "html");
  }

  private void handleHtmlResponseForImage(String analysisReportHtml) {
    assertThat(analysisReportHtml).contains("svg", "html");
  }

  private void mockMavenDependencyTree(Ecosystem.Type packageManager) throws IOException {
    if (packageManager.equals(Ecosystem.Type.MAVEN)) {
      mockedOperations = mockStatic(Operations.class);
      String depTree;
      try (var is = getResourceAsStreamDecision(getClass(), "tst_manifests/it/maven/depTree.txt")) {
        depTree = new String(is.readAllBytes());
      }
      mockedOperations
          .when(() -> Operations.runProcess(any(), any(), any()))
          .thenAnswer(
              invocationOnMock ->
                  getOutputFileAndOverwriteItWithMock(depTree, invocationOnMock, "-DoutputFile"));
      mockedOperations
          .when(() -> Operations.getCustomPathOrElse(anyString()))
          .thenReturn(packageManager.getExecutableShortName());
      mockedOperations
          .when(() -> Operations.getExecutable(anyString(), anyString()))
          .thenReturn(packageManager.getExecutableShortName());
    }
  }

  public static String getOutputFileAndOverwriteItWithMock(
      String outputFileContent, InvocationOnMock invocationOnMock, String parameterPrefix)
      throws IOException {
    String[] rawArguments = (String[]) invocationOnMock.getRawArguments()[1];
    Optional<String> outputFileArg =
        Arrays.stream(rawArguments)
            .filter(arg -> arg != null && arg.startsWith(parameterPrefix))
            .findFirst();
    String outputFilePath = null;
    if (outputFileArg.isPresent()) {
      String outputFile = outputFileArg.get();
      outputFilePath = outputFile.substring(outputFile.indexOf("=") + 1);
      Files.writeString(Path.of(outputFilePath), outputFileContent);
    }
    return outputFilePath;
  }
}
