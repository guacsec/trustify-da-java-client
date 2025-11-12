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
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.redhat.exhort.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("gitTest")
class GoModulesMainModuleVersionTest {

  private Path noGitRepo;
  private Path testGitRepo;
  private GoModulesProvider goModulesProvider;

  @BeforeEach
  void setUp() {
    try {
      this.goModulesProvider = new GoModulesProvider(null);
      this.testGitRepo = Files.createTempDirectory("TRUSTIFY_DA_tmp");
      gitInit();
      this.noGitRepo = Files.createTempDirectory("TRUSTIFY_DA_tmp");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @AfterEach
  void tearDown() {
    try {
      FileUtils.deleteDirectory(this.testGitRepo.toFile());
      FileUtils.deleteDirectory(this.noGitRepo.toFile());

    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  void determine_Main_Module_Version_NoRepo() {
    goModulesProvider.determineMainModuleVersion(noGitRepo);
    assertEquals(GoModulesProvider.DEFAULT_MAIN_VERSION, goModulesProvider.getMainModuleVersion());
  }

  @Test
  void determine_Main_Module_Version_GitRepo() {
    goModulesProvider.determineMainModuleVersion(testGitRepo);
    assertEquals(GoModulesProvider.DEFAULT_MAIN_VERSION, goModulesProvider.getMainModuleVersion());
  }

  @Test
  void determine_Main_Module_Version_GitRepo_commit_is_tag() {
    gitCommit("sample");
    gitTag("v1.0.0", "sample tag");

    goModulesProvider.determineMainModuleVersion(testGitRepo);
    assertEquals("v1.0.0", goModulesProvider.getMainModuleVersion());
  }

  @Test
  void determine_Main_Module_Version_GitRepo_commit_is_annotated_tag() {
    gitCommit("sample");
    gitTag("v1.0.0a", "annotatedTag");

    goModulesProvider.determineMainModuleVersion(testGitRepo);
    assertEquals("v1.0.0a", goModulesProvider.getMainModuleVersion());
  }

  @Test
  void determine_Main_Module_Version_GitRepo_commit_is_after_tag() {

    gitCommit("sample");
    gitTag("v1.0.0", "sample tag");
    gitCommit("sample-2");

    goModulesProvider.determineMainModuleVersion(testGitRepo);
    assertThat(goModulesProvider.getMainModuleVersion()).matches("v1.0.1-0.[0-9]{14}-[a-f0-9]{12}");
  }

  private void gitInit() {
    Operations.runProcessGetOutput(testGitRepo, "git", "-c", getConfigParam(), "init");
  }

  private void gitCommit(String message) {
    Operations.runProcessGetOutput(
        testGitRepo, "git", "-c", getConfigParam(), "commit", "-m", message, "--allow-empty");
  }

  private void gitTag(String tag, String message) {
    Operations.runProcessGetOutput(
        testGitRepo, "git", "-c", getConfigParam(), "tag", "-a", tag, "-m", message);
  }

  private String getConfigParam() {
    String absPath = Path.of("src/test/resources/git_config").toAbsolutePath().toString();
    return "include.path=" + absPath;
  }
}
