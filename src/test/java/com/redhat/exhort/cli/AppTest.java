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
package com.redhat.exhort.cli;

import static com.redhat.exhort.cli.AppUtils.exitWithError;
import static com.redhat.exhort.cli.AppUtils.printException;
import static com.redhat.exhort.cli.AppUtils.printLine;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.redhat.exhort.ExhortTest;
import com.redhat.exhort.api.v4.AnalysisReport;
import com.redhat.exhort.api.v4.ProviderReport;
import com.redhat.exhort.api.v4.ProviderStatus;
import com.redhat.exhort.api.v4.Scanned;
import com.redhat.exhort.api.v4.Source;
import com.redhat.exhort.api.v4.SourceSummary;
import com.redhat.exhort.impl.ExhortApi;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AppTest extends ExhortTest {

  private static final Path TEST_FILE = Paths.get("/test/path/manifest.xml");
  private static final String NON_EXISTENT_FILE = "/non/existent/file.xml";
  private static final String DIRECTORY_PATH = "/some/directory";

  @Test
  void main_with_no_args_should_print_help() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[0]);

      mockedAppUtils.verify(() -> printLine(contains("Exhort Java API CLI")));
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"--help", "-h"})
  void main_with_help_flag_should_print_help(String helpFlag) {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {helpFlag});

      mockedAppUtils.verify(() -> printLine(contains("Exhort Java API CLI")));
      mockedAppUtils.verify(() -> printLine(contains("USAGE:")));
      mockedAppUtils.verify(
          () ->
              printLine(contains("java -jar exhort-java-api.jar <COMMAND> <FILE_PATH> [OPTIONS]")));
    }
  }

  @Test
  void main_with_help_flag_after_other_args_should_print_help() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack", "--help"});

      mockedAppUtils.verify(() -> printLine(contains("Exhort Java API CLI")));
    }
  }

  @Test
  void help_should_contain_usage_section() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      mockedAppUtils.verify(() -> printLine(contains("USAGE:")));
      mockedAppUtils.verify(
          () ->
              printLine(contains("java -jar exhort-java-api.jar <COMMAND> <FILE_PATH> [OPTIONS]")));
    }
  }

  @Test
  void help_should_contain_commands_section() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      mockedAppUtils.verify(() -> printLine(contains("COMMANDS:")));
      mockedAppUtils.verify(() -> printLine(contains("stack <file_path> [--summary|--html]")));
      mockedAppUtils.verify(() -> printLine(contains("component <file_path> [--summary]")));
    }
  }

  @Test
  void help_should_contain_stack_command_description() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      mockedAppUtils.verify(
          () -> printLine(contains("Perform stack analysis on the specified manifest file")));
      mockedAppUtils.verify(
          () -> printLine(contains("--summary    Output summary in JSON format")));
      mockedAppUtils.verify(
          () -> printLine(contains("--html       Output full report in HTML format")));
      mockedAppUtils.verify(
          () -> printLine(contains("(default)    Output full report in JSON format")));
    }
  }

  @Test
  void help_should_contain_component_command_description() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      mockedAppUtils.verify(
          () -> printLine(contains("Perform component analysis on the specified manifest file")));
      mockedAppUtils.verify(
          () -> printLine(contains("--summary    Output summary in JSON format")));
      mockedAppUtils.verify(
          () -> printLine(contains("(default)    Output full report in JSON format")));
    }
  }

  @Test
  void help_should_contain_options_section() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      mockedAppUtils.verify(() -> printLine(contains("OPTIONS:")));
      mockedAppUtils.verify(() -> printLine(contains("-h, --help     Show this help message")));
    }
  }

  @Test
  void help_should_contain_examples_section() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      mockedAppUtils.verify(() -> printLine(contains("EXAMPLES:")));
      mockedAppUtils.verify(
          () -> printLine(contains("java -jar exhort-java-api.jar stack /path/to/pom.xml")));
      mockedAppUtils.verify(
          () ->
              printLine(
                  contains("java -jar exhort-java-api.jar stack /path/to/package.json --summary")));
      mockedAppUtils.verify(
          () ->
              printLine(
                  contains("java -jar exhort-java-api.jar stack /path/to/build.gradle --html")));
      mockedAppUtils.verify(
          () ->
              printLine(
                  contains("java -jar exhort-java-api.jar component /path/to/requirements.txt")));
    }
  }

  @Test
  void main_with_missing_arguments_should_exit_with_error() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack"});

      // The app should print exception and exit - matches actual App.java behavior
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_invalid_command_should_exit_with_error() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"invalidcommand", "somefile.txt"});

      // The app should print exception and exit - matches actual App.java behavior
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void help_loads_from_external_file() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"--help"});

      // Verify that help content is printed (loaded from cli_help.txt)
      mockedAppUtils.verify(() -> printLine(contains("Exhort Java API CLI")));
      mockedAppUtils.verify(() -> printLine(contains("USAGE:")));
      mockedAppUtils.verify(() -> printLine(contains("COMMANDS:")));
      mockedAppUtils.verify(() -> printLine(contains("EXAMPLES:")));
    }
  }

  @Test
  void executeCommand_with_stack_analysis_should_complete_successfully() throws Exception {
    // Create CliArgs
    CliArgs args = new CliArgs(Command.STACK, TEST_FILE, OutputFormat.JSON);

    // Mock the AnalysisReport
    AnalysisReport mockReport = mock(AnalysisReport.class);

    // Mock ExhortApi constructor and its methods
    try (MockedConstruction<ExhortApi> mockedExhortApi =
        mockConstruction(
            ExhortApi.class,
            (mock, context) -> {
              when(mock.stackAnalysis(any(String.class)))
                  .thenReturn(CompletableFuture.completedFuture(mockReport));
            })) {

      // Use reflection to access the private executeCommand method
      Method executeCommandMethod = App.class.getDeclaredMethod("executeCommand", CliArgs.class);
      executeCommandMethod.setAccessible(true);

      // Execute the method
      CompletableFuture<String> result =
          (CompletableFuture<String>) executeCommandMethod.invoke(null, args);

      // Verify the result
      assertThat(result).isNotNull();
      assertThat(result.get()).isNotNull();
    }
  }

  @Test
  void executeCommand_with_component_analysis_should_complete_successfully() throws Exception {
    // Create CliArgs
    CliArgs args = new CliArgs(Command.COMPONENT, TEST_FILE, OutputFormat.SUMMARY);

    // Mock the AnalysisReport
    AnalysisReport mockReport = mock(AnalysisReport.class);

    // Mock ExhortApi constructor and its methods
    try (MockedConstruction<ExhortApi> mockedExhortApi =
        mockConstruction(
            ExhortApi.class,
            (mock, context) -> {
              when(mock.componentAnalysis(any(String.class)))
                  .thenReturn(CompletableFuture.completedFuture(mockReport));
            })) {

      // Use reflection to access the private executeCommand method
      Method executeCommandMethod = App.class.getDeclaredMethod("executeCommand", CliArgs.class);
      executeCommandMethod.setAccessible(true);

      // Execute the method
      CompletableFuture<String> result =
          (CompletableFuture<String>) executeCommandMethod.invoke(null, args);

      // Verify the result
      assertThat(result).isNotNull();
      assertThat(result.get()).isNotNull();
    }
  }

  @Test
  void executeCommand_with_IOException_should_propagate_exception() throws Exception {
    // Create CliArgs
    CliArgs args = new CliArgs(Command.STACK, TEST_FILE, OutputFormat.JSON);

    // Mock ExhortApi constructor to throw IOException
    try (MockedConstruction<ExhortApi> mockedExhortApi =
        mockConstruction(
            ExhortApi.class,
            (mock, context) -> {
              when(mock.stackAnalysis(any(String.class)))
                  .thenThrow(new IOException("Network error"));
            })) {

      // Use reflection to access the private executeCommand method
      Method executeCommandMethod = App.class.getDeclaredMethod("executeCommand", CliArgs.class);
      executeCommandMethod.setAccessible(true);

      // Execute and verify exception
      assertThatThrownBy(
              () -> {
                executeCommandMethod.invoke(null, args);
              })
          .hasCauseInstanceOf(IOException.class);
    }
  }

  @Test
  void executeCommand_with_ExecutionException_should_propagate_exception() throws Exception {
    // Create CliArgs
    CliArgs args = new CliArgs(Command.COMPONENT, TEST_FILE, OutputFormat.JSON);

    // Create a failed future to simulate ExecutionException
    CompletableFuture<AnalysisReport> failedFuture = new CompletableFuture<>();
    failedFuture.completeExceptionally(new RuntimeException("Analysis failed"));

    // Mock ExhortApi constructor
    try (MockedConstruction<ExhortApi> mockedExhortApi =
        mockConstruction(
            ExhortApi.class,
            (mock, context) -> {
              when(mock.componentAnalysis(any(String.class))).thenReturn(failedFuture);
            })) {

      // Use reflection to access the private executeCommand method
      Method executeCommandMethod = App.class.getDeclaredMethod("executeCommand", CliArgs.class);
      executeCommandMethod.setAccessible(true);

      // Execute the method
      CompletableFuture<String> result =
          (CompletableFuture<String>) executeCommandMethod.invoke(null, args);

      // Verify the result throws ExecutionException when accessed
      assertThatThrownBy(() -> result.get()).isInstanceOf(ExecutionException.class);
    }
  }

  @Test
  void main_with_invalid_file_should_handle_IOException() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack", "/non/existent/file.xml"});

      // Verify that the exception is caught and handled
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_directory_instead_of_file_should_handle_IOException() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack", DIRECTORY_PATH});

      // Verify that the exception is caught and handled
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_execution_exception_should_handle_gracefully() {
    // Test with a file path that will cause ExecutionException in processing
    String unsupportedFile = "/path/to/unsupported.txt";

    // Create a failed future to simulate ExecutionException
    CompletableFuture<AnalysisReport> failedFuture = new CompletableFuture<>();
    failedFuture.completeExceptionally(new RuntimeException("Analysis failed"));

    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.stackAnalysis(any(String.class))).thenReturn(failedFuture);
                })) {

      App.main(new String[] {"stack", unsupportedFile});

      // Verify that the exception is caught and handled
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void command_enum_should_have_correct_values() {
    assertThat(Command.STACK).isNotNull();
    assertThat(Command.COMPONENT).isNotNull();
    assertThat(Command.values()).hasSize(2);
    assertThat(Command.valueOf("STACK")).isEqualTo(Command.STACK);
    assertThat(Command.valueOf("COMPONENT")).isEqualTo(Command.COMPONENT);
  }

  @Test
  void output_format_enum_should_have_correct_values() {
    assertThat(OutputFormat.JSON).isNotNull();
    assertThat(OutputFormat.HTML).isNotNull();
    assertThat(OutputFormat.SUMMARY).isNotNull();
    assertThat(OutputFormat.values()).hasSize(3);
    assertThat(OutputFormat.valueOf("JSON")).isEqualTo(OutputFormat.JSON);
    assertThat(OutputFormat.valueOf("HTML")).isEqualTo(OutputFormat.HTML);
    assertThat(OutputFormat.valueOf("SUMMARY")).isEqualTo(OutputFormat.SUMMARY);
  }

  @Test
  void cli_args_should_store_values_correctly() {
    CliArgs args = new CliArgs(Command.STACK, TEST_FILE, OutputFormat.JSON);

    assertThat(args.command).isEqualTo(Command.STACK);
    assertThat(args.filePath).isEqualTo(TEST_FILE);
    assertThat(args.outputFormat).isEqualTo(OutputFormat.JSON);
  }

  @Test
  void app_utils_exit_methods_should_be_mockable() {
    // These will actually call System.exit(), so we test them with mocking
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      exitWithError();

      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_invalid_command_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"invalidcommand", "pom.xml"});

      // Verify that the exception is caught and handled
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_unknown_command_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"unknown", "pom.xml"});

      // Verify that the exception is caught and handled
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_empty_command_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"", "pom.xml"});

      // Verify that the exception is caught and handled
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_valid_formats_should_work_with_mocked_api() {
    // Mock the AnalysisReport
    AnalysisReport mockReport = defaultAnalysisReport();

    // Test summary format for stack command
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.stackAnalysis(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(mockReport));
                })) {

      App.main(new String[] {"stack", "pom.xml", "--summary"});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }

    // Test HTML format for stack command
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.stackAnalysisHtml(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(new byte[0]));
                })) {

      App.main(new String[] {"stack", "pom.xml", "--html"});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }

    // Test summary format for component command
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.componentAnalysis(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(mockReport));
                })) {

      App.main(new String[] {"component", "pom.xml", "--summary"});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }
  }

  @Test
  void main_for_component_should_handle_interrupted_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.componentAnalysis(any(String.class)))
                      .thenThrow(new IOException("Example exception"));
                })) {

      App.main(new String[] {"component", "pom.xml", "--summary"});

      mockedAppUtils.verify(() -> printException(any(IOException.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_html_for_component_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"component", "pom.xml", "--html"});

      // HTML format is not supported for component analysis
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_invalid_format_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack", "pom.xml", "--invalid"});

      // Invalid format should cause exception
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_xml_format_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"component", "pom.xml", "--xml"});

      // XML format is not supported
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_valid_existing_file_should_work_with_mocked_api() {
    // Mock the AnalysisReport
    AnalysisReport mockReport = mock(AnalysisReport.class);

    // Test with the current pom.xml file which should exist
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.stackAnalysis(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(mockReport));
                })) {

      App.main(new String[] {"stack", "pom.xml"});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }

    // Test with absolute path to pom.xml
    String absolutePomPath = System.getProperty("user.dir") + "/pom.xml";
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.componentAnalysis(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(mockReport));
                })) {

      App.main(new String[] {"component", absolutePomPath});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }
  }

  @Test
  void main_with_non_existent_file_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack", NON_EXISTENT_FILE});

      // File validation should fail
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_definitely_non_existent_file_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"component", "/definitely/does/not/exist.xml"});

      // File validation should fail
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_tmp_directory_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"stack", "/tmp"});

      // Directory validation should fail
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_system_temp_directory_should_handle_exception() {
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
      App.main(new String[] {"component", System.getProperty("java.io.tmpdir")});

      // Directory validation should fail
      mockedAppUtils.verify(() -> printException(any(Exception.class)));
      mockedAppUtils.verify(() -> exitWithError());
    }
  }

  @Test
  void main_with_default_json_format_should_work_with_mocked_api() {
    // Mock the AnalysisReport
    AnalysisReport mockReport = mock(AnalysisReport.class);

    // Test default JSON format for stack command (no format flag)
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.stackAnalysis(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(mockReport));
                })) {

      App.main(new String[] {"stack", "pom.xml"});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }

    // Test default JSON format for component command (no format flag)
    try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class);
        MockedConstruction<ExhortApi> mockedExhortApi =
            mockConstruction(
                ExhortApi.class,
                (mock, context) -> {
                  when(mock.componentAnalysis(any(String.class)))
                      .thenReturn(CompletableFuture.completedFuture(mockReport));
                })) {

      App.main(new String[] {"component", "pom.xml"});

      mockedAppUtils.verify(() -> printLine(any(String.class)));
    }
  }

  private AnalysisReport defaultAnalysisReport() {
    AnalysisReport report = new AnalysisReport();
    report.setScanned(new Scanned().direct(10).transitive(10).total(20));
    report.putProvidersItem(
        "tpa",
        new ProviderReport()
            .status(new ProviderStatus().code(200).message("OK"))
            .putSourcesItem("osv", new Source().summary(new SourceSummary())));
    return report;
  }
}
