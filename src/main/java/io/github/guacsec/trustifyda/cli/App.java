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
package io.github.guacsec.trustifyda.cli;

import static io.github.guacsec.trustifyda.cli.AppUtils.exitWithError;
import static io.github.guacsec.trustifyda.cli.AppUtils.printException;
import static io.github.guacsec.trustifyda.cli.AppUtils.printLine;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.guacsec.trustifyda.Api;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.ProviderReport;
import io.github.guacsec.trustifyda.api.v5.SourceSummary;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.image.ImageUtils;
import io.github.guacsec.trustifyda.impl.ExhortApi;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class App {

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String CLI_HELPTXT = "cli_help.txt";

  static {
    MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
  }

  public static void main(String[] args) {
    if (args.length == 0 || isHelpRequested(args)) {
      printHelp();
      return;
    }

    try {
      CliArgs cliArgs = parseArgs(args);
      String result = executeCommand(cliArgs).get();
      printLine(result);
    } catch (IllegalArgumentException e) {
      printException(e);
      printHelp();
      exitWithError();
    } catch (IOException | InterruptedException | ExecutionException e) {
      printException(e);
      exitWithError();
    }
  }

  private static boolean isHelpRequested(String[] args) {
    for (String arg : args) {
      if ("--help".equals(arg) || "-h".equals(arg)) {
        return true;
      }
    }
    return false;
  }

  private static CliArgs parseArgs(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException("Missing required arguments");
    }

    Command command = parseCommand(args[0]);

    switch (command) {
      case STACK:
      case COMPONENT:
        return parseFileBasedArgs(command, args);
      case IMAGE:
        return parseImageBasedArgs(command, args);
      default:
        throw new IllegalArgumentException("Unsupported command: " + command);
    }
  }

  private static CliArgs parseFileBasedArgs(Command command, String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException("Missing required file path for " + command + " command");
    }

    Path path = validateFile(args[1]);

    OutputFormat outputFormat = OutputFormat.JSON;
    if (args.length == 3) {
      outputFormat = parseOutputFormat(command, args[2]);
    } else if (args.length > 3) {
      throw new IllegalArgumentException("Too many arguments for " + command + " command");
    }

    return new CliArgs(command, path, outputFormat);
  }

  private static CliArgs parseImageBasedArgs(Command command, String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
          "Missing required image references for " + command + " command");
    }

    OutputFormat outputFormat = OutputFormat.JSON;
    int imageArgCount = args.length - 1;

    if (args.length >= 3) {
      String lastArg = args[args.length - 1];
      if (lastArg.startsWith("--")) {
        outputFormat = parseOutputFormat(command, lastArg);
        imageArgCount = args.length - 2;
      }
    }

    if (imageArgCount < 1) {
      throw new IllegalArgumentException(
          "At least one image reference is required for " + command + " command");
    }

    Set<ImageRef> imageRefs = new HashSet<>();
    for (int i = 1; i <= imageArgCount; i++) {
      try {
        ImageRef imageRef = ImageUtils.parseImageRef(args[i]);
        imageRefs.add(imageRef);
      } catch (Exception e) {
        throw new IllegalArgumentException(
            "Invalid image reference '" + args[i] + "': " + e.getMessage(), e);
      }
    }

    return new CliArgs(command, imageRefs, outputFormat);
  }

  private static Command parseCommand(String commandStr) {
    switch (commandStr) {
      case "stack":
        return Command.STACK;
      case "component":
        return Command.COMPONENT;
      case "image":
        return Command.IMAGE;
      default:
        throw new IllegalArgumentException(
            "Unknown command: " + commandStr + ". Use 'stack', 'component', or 'image'");
    }
  }

  private static OutputFormat parseOutputFormat(Command command, String formatArg) {
    switch (formatArg) {
      case "--summary":
        return OutputFormat.SUMMARY;
      case "--html":
        if (command != Command.STACK && command != Command.IMAGE) {
          throw new IllegalArgumentException(
              "HTML format is only supported for stack and image commands");
        }
        return OutputFormat.HTML;
      default:
        throw new IllegalArgumentException(
            "Unknown option for " + command + " command: " + formatArg);
    }
  }

  private static Path validateFile(String filePath) {
    Path path = Paths.get(filePath);
    if (!Files.exists(path)) {
      throw new IllegalArgumentException("File does not exist: " + filePath);
    }
    if (!Files.isRegularFile(path)) {
      throw new IllegalArgumentException("File is not a regular file: " + filePath);
    }
    return path;
  }

  private static CompletableFuture<String> executeCommand(CliArgs args) throws IOException {
    switch (args.command) {
      case STACK:
        return executeStackAnalysis(args.filePath.toAbsolutePath().toString(), args.outputFormat);
      case COMPONENT:
        return executeComponentAnalysis(
            args.filePath.toAbsolutePath().toString(), args.outputFormat);
      case IMAGE:
        return executeImageAnalysis(args.imageRefs, args.outputFormat);
      default:
        throw new AssertionError();
    }
  }

  private static CompletableFuture<String> executeStackAnalysis(
      String filePath, OutputFormat outputFormat) throws IOException {
    Api api = new ExhortApi();
    switch (outputFormat) {
      case JSON:
        return api.stackAnalysis(filePath).thenApply(App::toJsonString);
      case HTML:
        return api.stackAnalysisHtml(filePath).thenApply(bytes -> new String(bytes));
      case SUMMARY:
        return api.stackAnalysis(filePath)
            .thenApply(App::extractSummary)
            .thenApply(App::toJsonString);
      default:
        throw new AssertionError();
    }
  }

  private static CompletableFuture<String> executeComponentAnalysis(
      String filePath, OutputFormat outputFormat) throws IOException {
    Api api = new ExhortApi();
    CompletableFuture<AnalysisReport> analysis = api.componentAnalysis(filePath);
    if (outputFormat.equals(OutputFormat.SUMMARY)) {
      var summary = analysis.thenApply(App::extractSummary);
      return summary.thenApply(App::toJsonString);
    }
    return analysis.thenApply(App::toJsonString);
  }

  private static String toJsonString(Object obj) {
    try {
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to serialize to JSON", e);
    }
  }

  private static CompletableFuture<String> executeImageAnalysis(
      Set<ImageRef> imageRefs, OutputFormat outputFormat) throws IOException {
    Api api = new ExhortApi();
    switch (outputFormat) {
      case JSON:
        return api.imageAnalysis(imageRefs).thenApply(App::formatImageAnalysisResult);
      case HTML:
        return api.imageAnalysisHtml(imageRefs).thenApply(bytes -> new String(bytes));
      case SUMMARY:
        return api.imageAnalysis(imageRefs)
            .thenApply(App::extractImageSummary)
            .thenApply(App::toJsonString);
      default:
        throw new AssertionError();
    }
  }

  private static String formatImageAnalysisResult(Map<ImageRef, AnalysisReport> analysisResults) {
    try {
      return MAPPER.writeValueAsString(analysisResults);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to serialize image analysis results", e);
    }
  }

  private static Map<String, Map<String, SourceSummary>> extractImageSummary(
      Map<ImageRef, AnalysisReport> analysisResults) {
    Map<String, Map<String, SourceSummary>> imageSummaries = new HashMap<>();

    for (Map.Entry<ImageRef, AnalysisReport> entry : analysisResults.entrySet()) {
      String imageKey = entry.getKey().toString();
      Map<String, SourceSummary> imageSummary = extractSummary(entry.getValue());
      imageSummaries.put(imageKey, imageSummary);
    }

    return imageSummaries;
  }

  private static Map<String, SourceSummary> extractSummary(AnalysisReport report) {
    Map<String, SourceSummary> summary = new HashMap<>();
    if (report.getProviders() == null) {
      return summary;
    }
    report
        .getProviders()
        .entrySet()
        .forEach(
            entry -> {
              var provider = new ProviderReport();
              provider.setStatus(entry.getValue().getStatus());
              if (entry.getValue().getSources() != null) {
                entry
                    .getValue()
                    .getSources()
                    .entrySet()
                    .forEach(
                        sourceEntry -> {
                          if (sourceEntry.getValue().getSummary() != null) {
                            summary.put(sourceEntry.getKey(), sourceEntry.getValue().getSummary());
                          }
                        });
              }
            });
    return summary;
  }

  private static void printHelp() {
    try (var inputStream = App.class.getClassLoader().getResourceAsStream(CLI_HELPTXT)) {
      if (inputStream == null) {
        AppUtils.printError("Help file not found.");
        return;
      }

      String helpText = new String(inputStream.readAllBytes());
      printLine(helpText);
    } catch (IOException e) {
      AppUtils.printError("Error reading help file: " + e.getMessage());
    }
  }
}
