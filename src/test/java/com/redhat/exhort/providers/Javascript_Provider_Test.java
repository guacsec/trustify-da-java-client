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
package com.redhat.exhort.providers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mockStatic;

import com.redhat.exhort.Api;
import com.redhat.exhort.ExhortTest;
import com.redhat.exhort.tools.Ecosystem;
import com.redhat.exhort.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

@ExtendWith(HelperExtension.class)
class Javascript_Provider_Test extends ExhortTest {
  // test folder are located at src/test/resources/tst_manifests/npm
  // each folder should contain:
  // - package.json: the target manifest for testing
  // - expected_sbom.json: the SBOM expected to be provided
  static Stream<String> testFolders() {
    return Stream.of("deps_with_ignore", "deps_with_no_ignore");
  }

  static Stream<String> providers() {
    return Stream.of(
        Ecosystem.Type.NPM.getType(), Ecosystem.Type.PNPM.getType(), "yarn-classic", "yarn-berry");
  }

  static Stream<Arguments> testCases() {
    return providers().flatMap(p -> testFolders().map(f -> Arguments.of(p, f)));
  }

  @ParameterizedTest
  @MethodSource({"testCases"})
  void test_the_provideStack(String pkgManager, String testFolder) throws IOException {
    // create temp file hosting our sut package.json
    var tmpFolder = Files.createTempDirectory("TRUSTIFY_DA_test_");
    var tmpFile = Files.createFile(tmpFolder.resolve("package.json"));
    var tmpLockFile = Files.createFile(tmpFolder.resolve(getLockFile(pkgManager)));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/%s/%s/package.json", pkgManager, testFolder))) {
      Files.write(tmpFile, is.readAllBytes());
    }

    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/%s/%s/%s", pkgManager, testFolder, getLockFile(pkgManager)))) {
      Files.write(tmpLockFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/%s/%s/expected_stack_sbom.json", pkgManager, testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String listingStack;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/%s/%s/%s-ls-stack.json", pkgManager, testFolder, pkgManager))) {
      listingStack = new String(is.readAllBytes());
    }

    try (MockedStatic<Operations> mockedOperations =
        mockOperations(pkgManager, listingStack, false)) {
      // when providing stack content for our pom
      var content = JavaScriptProviderFactory.create(tmpFile).provideStack();
      // cleanup
      Files.deleteIfExists(tmpFile);
      Files.deleteIfExists(tmpLockFile);
      Files.deleteIfExists(tmpFolder);
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  @ParameterizedTest
  @MethodSource({"testCases"})
  void test_the_provideComponent(String pkgManager, String testFolder) throws IOException {
    // load the pom target pom file
    var targetPom =
        String.format(
            "src/test/resources/tst_manifests/%s/%s/package.json", pkgManager, testFolder);
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/npm/common/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String listingComponent;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/%s/%s/%s-ls-component.json", pkgManager, testFolder, pkgManager))) {
      listingComponent = new String(is.readAllBytes());
    }

    try (MockedStatic<Operations> mockedOperations =
        mockOperations(pkgManager, listingComponent, false)) {
      // when providing component content for our pom
      var content = JavaScriptProviderFactory.create(Path.of(targetPom)).provideComponent();
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  @ParameterizedTest
  @MethodSource("testCases")
  void test_the_provideComponent_with_Path(String pkgManager, String testFolder) throws Exception {
    // load the pom target pom file

    // create temp file hosting our sut package.json
    var tmpFolder = Files.createTempDirectory("TRUSTIFY_DA_test_");
    var tmpFile = Files.createFile(tmpFolder.resolve("package.json"));

    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/%s/%s/package.json", pkgManager, testFolder))) {
      Files.write(tmpFile, is.readAllBytes());
    }
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/%s/%s/%s", pkgManager, testFolder, getLockFile(pkgManager)))) {
      Files.write(tmpFolder.resolve(getLockFile(pkgManager)), is.readAllBytes());
    }
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/npm/common/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String listingComponent;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/%s/%s/%s-ls-component.json", pkgManager, testFolder, pkgManager))) {
      listingComponent = new String(is.readAllBytes());
    }
    try (MockedStatic<Operations> mockedOperations =
        mockOperations(pkgManager, listingComponent, true)) {
      // when providing component content for our pom
      var provider = JavaScriptProviderFactory.create(tmpFile);
      var content = provider.provideComponent();
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  private String dropIgnored(String s) {
    return s.replaceAll("\\s+", "").replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"", "");
  }

  private String getLockFile(String pkgManager) {
    Ecosystem.Type mgr;
    if (pkgManager.startsWith(Ecosystem.Type.YARN.getType().toLowerCase())) {
      mgr = Ecosystem.Type.YARN;
    } else {
      mgr = Ecosystem.Type.valueOf(pkgManager.toUpperCase());
    }
    switch (mgr) {
      case NPM:
        return JavaScriptNpmProvider.LOCK_FILE;
      case PNPM:
        return JavaScriptPnpmProvider.LOCK_FILE;
      case YARN:
        return JavaScriptYarnProvider.LOCK_FILE;
      default:
        fail("Unexpected pkg manager: " + pkgManager);
        return null;
    }
  }

  private MockedStatic<Operations> mockOperations(
      String pkgManager, String listResult, boolean withPath) {
    var mockedOperations = mockStatic(Operations.class);
    if (pkgManager.equalsIgnoreCase("yarn-classic")) {
      mockedOperations
          .when(() -> Operations.runProcessGetOutput(any(), any(), isNull()))
          .thenReturn("1.22.22", listResult);
    } else if (pkgManager.equalsIgnoreCase("yarn-berry")) {
      mockedOperations
          .when(() -> Operations.runProcessGetOutput(any(), any(), isNull()))
          .thenReturn("4.9.1", listResult);
    } else {
      mockedOperations
          .when(() -> Operations.runProcessGetOutput(any(), any(), isNull()))
          .thenReturn(listResult);
    }

    // Mock for yarn
    mockedOperations.when(() -> Operations.getCustomPathOrElse(eq("yarn"))).thenReturn("yarn");
    mockedOperations
        .when(() -> Operations.getExecutable(eq("yarn"), anyString()))
        .thenReturn("yarn");
    // Mock for other pkgManager values (return pkgManager as-is)
    mockedOperations
        .when(() -> Operations.getCustomPathOrElse(eq(pkgManager)))
        .thenReturn(pkgManager);
    mockedOperations
        .when(() -> Operations.getExecutable(eq(pkgManager), any()))
        .thenReturn(pkgManager);
    return mockedOperations;
  }
}
