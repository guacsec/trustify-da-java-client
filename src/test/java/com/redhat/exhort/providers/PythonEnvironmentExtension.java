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

import com.redhat.exhort.tools.Operations;
import com.redhat.exhort.utils.PythonControllerBase;
import com.redhat.exhort.utils.PythonControllerTestEnv;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

public class PythonEnvironmentExtension
    implements BeforeAllCallback,
        AfterAllCallback,
        BeforeEachCallback,
        AfterEachCallback,
        ParameterResolver,
        BeforeTestExecutionCallback {

  private PythonControllerBase pythonController =
      new PythonControllerTestEnv(
          Operations.getCustomPathOrElse("python3"), Operations.getCustomPathOrElse("pip3"));
  private final System.Logger log = System.getLogger(this.getClass().getName());

  @Override
  public void afterAll(ExtensionContext extensionContext) {
    log.log(System.Logger.Level.INFO, "Finished all python tests and about to clean environment");
    pythonController.cleanEnvironment(true);
  }

  @Override
  public void afterEach(ExtensionContext extensionContext) {
    log.log(
        System.Logger.Level.INFO,
        String.format("Finished Test Method: %s", extensionContext.getRequiredTestMethod()));
  }

  @Override
  public void beforeAll(ExtensionContext extensionContext) {
    log.log(System.Logger.Level.INFO, "Preparing python environment for tests");
    String python3 = Operations.getCustomPathOrElse("python3");
    String pip3 = Operations.getCustomPathOrElse("pip3");
    this.pythonController = new PythonControllerTestEnv(python3, pip3);
    log.log(System.Logger.Level.INFO, "Finished Preparing environment for testing");
    //    var tmpPythonModuleDir = Files.createTempDirectory("exhort_test_");
    //    var tmpPythonFile = Files.createFile(tmpPythonModuleDir.resolve("requirements.txt"));
    //    Python_Provider_Test.testFolders().forEach( test -> {
    //      try (var is =
    // getClass().getClassLoader().getResourceAsStream(String.join("/","tst_manifests", "pip",
    // test, "requirements.txt"))) {
    //        Files.write(tmpPythonFile, is.readAllBytes());
    //        pythonController.installPackage(tmpPythonFile.toAbsolutePath().toString());
    //
    //      } catch (IOException e) {
    //        throw new RuntimeException(e);
    //      }
    //    });
    //    log.log(System.Logger.Level.INFO,"Finished Installing all requirements.txt files");
    //    Files.deleteIfExists(tmpPythonFile);
    //    Files.deleteIfExists(tmpPythonModuleDir);

  }

  @Override
  public void beforeEach(ExtensionContext extensionContext) {
    log.log(
        System.Logger.Level.INFO,
        String.format("About to Start Test Method: %s", extensionContext.getRequiredTestMethod()));
  }

  @Override
  public boolean supportsParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return parameterContext.getParameter().getType().equals(PythonControllerBase.class)
        || parameterContext.getParameter().getType().equals(PythonControllerTestEnv.class);
  }

  @Override
  public Object resolveParameter(
      ParameterContext parameterContext, ExtensionContext extensionContext)
      throws ParameterResolutionException {
    return this.pythonController;
  }

  @Override
  public void beforeTestExecution(ExtensionContext extensionContext) {
    //    Method requiredTestMethod = extensionContext.getRequiredTestInstances();
  }
}
