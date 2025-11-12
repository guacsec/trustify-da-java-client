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
package io.github.guacsec.trustifyda.tools;

import static java.lang.String.join;

import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.utils.Environment;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/** Utility class used for executing process on the operating system. * */
public final class Operations {

  // Some package providers might return Unix output in Windows, so we need to use a generic line
  // separator
  public static final String GENERIC_LINE_SEPARATOR = "\\r?\\n";
  private static final Logger log = LoggersFactory.getLogger(Operations.class.getName());

  private Operations() {
    // constructor not required for a utility class
  }

  /**
   * Function for looking up custom executable path based on the default one provides as an
   * argument. I.e. if defaultExecutable=mvn, this function will look for a custom mvn path set as
   * an environment variable or a java property with the name TRUSTIFY_DA_MVN_PATH. If not found,
   * the original mvn passed as defaultExecutable will be returned. Note, environment variables
   * takes precedence on java properties.
   *
   * @param defaultExecutable default executable (uppercase spaces and dashes will be replaced with
   *     underscores).
   * @return the custom path from the relevant environment variable or the original argument.
   */
  public static String getCustomPathOrElse(String defaultExecutable) {
    String normalized = defaultExecutable;
    int dotIndex = normalized.indexOf('.');
    if (dotIndex > 0) {
      normalized = normalized.substring(0, dotIndex);
    }

    var target = normalized.toUpperCase().replaceAll(" ", "_").replaceAll("-", "_");
    var primaryKey = String.format("TRUSTIFY_DA_%s_PATH", target);
    String primary = Environment.get(primaryKey);
    if (primary != null) {
      return primary;
    }
    return defaultExecutable;
  }

  /**
   * Function for building a command from the command parts list and execute it as a process on the
   * operating system. Will throw a RuntimeException if the command build or execution failed.
   *
   * @param cmdList list of command parts
   */
  public static void runProcess(final String... cmdList) {
    runProcess(null, cmdList, null);
  }

  public static void runProcess(final Path workingDirectory, final String... cmdList) {
    runProcess(workingDirectory, cmdList, null);
  }

  public static void runProcess(final String[] cmdList, final Map<String, String> envMap) {
    runProcess(null, cmdList, null);
  }

  public static void runProcess(
      final Path workingDirectory, final String[] cmdList, final Map<String, String> envMap) {
    var processBuilder = new ProcessBuilder();
    processBuilder.command(cmdList);
    if (workingDirectory != null) {
      processBuilder.directory(workingDirectory.toFile());
    }
    if (envMap != null) {
      processBuilder.environment().putAll(envMap);
    }
    // create a process builder or throw a runtime exception
    Process process;
    try {
      process = processBuilder.start();
    } catch (final IOException e) {
      throw new RuntimeException(
          String.format(
              "failed to build process for '%s' got %s", join(" ", cmdList), e.getMessage()));
    }

    // execute the command or throw runtime exception if failed
    int exitCode;
    try {
      exitCode = process.waitFor();

    } catch (final InterruptedException e) {
      throw new RuntimeException(
          String.format(
              "built process for '%s' interrupted, got %s", join(" ", cmdList), e.getMessage()));
    }
    // verify the command was executed successfully or throw a runtime exception
    if (exitCode != 0) {
      String errMsg;
      try (var reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
        errMsg = reader.lines().collect(Collectors.joining(System.lineSeparator()));
      } catch (IOException e) {
        throw new RuntimeException(
            String.format(
                "unable to process error output for '%s', got %s",
                join(" ", cmdList), e.getMessage()));
      }

      if (errMsg.isEmpty()) {
        try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
          errMsg = reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (IOException e) {
          throw new RuntimeException(
              String.format(
                  "unable to process output for '%s', got %s", join(" ", cmdList), e.getMessage()));
        }
      }
      if (errMsg.isEmpty()) {
        throw new RuntimeException(
            String.format("failed to execute '%s', exit-code %d", join(" ", cmdList), exitCode));
      } else {
        throw new RuntimeException(
            String.format(
                "failed to execute '%s', exit-code %d, message:%s%s%s",
                join(" ", cmdList),
                exitCode,
                System.lineSeparator(),
                errMsg,
                System.lineSeparator()));
      }
    }
  }

  public static String runProcessGetOutput(Path dir, final String... cmdList) {
    return runProcessGetOutput(dir, cmdList, null);
  }

  public static String runProcessGetOutput(Path dir, final String[] cmdList, String[] envList) {
    try {
      Process process;
      if (dir == null) {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList);
        } else {
          process = Runtime.getRuntime().exec(cmdList, null);
        }
      } else {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList, dir.toFile());
        } else {
          process = Runtime.getRuntime().exec(cmdList, null, dir.toFile());
        }
      }

      String stdout = new String(process.getInputStream().readAllBytes());

      if (!stdout.isBlank()) {
        return stdout.trim();
      }
      // TODO: This should throw an exception if the process fails
      String stderr = new String(process.getErrorStream().readAllBytes());
      return stderr.trim();
    } catch (IOException e) {
      throw new RuntimeException(
          String.format("Failed to execute command '%s' ", join(" ", cmdList)), e);
    }
  }

  public static ProcessExecOutput runProcessGetFullOutput(
      Path dir, final String[] cmdList, String[] envList) {
    try {
      Process process;
      if (dir == null) {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList);
        } else {
          process = Runtime.getRuntime().exec(cmdList);
        }
      } else {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList, dir.toFile());
        } else {
          process = Runtime.getRuntime().exec(cmdList, null, dir.toFile());
        }
      }

      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      StringBuilder output = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line);
        if (!line.endsWith(System.lineSeparator())) {
          output.append("\n");
        }
      }

      reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
      StringBuilder error = new StringBuilder();
      while ((line = reader.readLine()) != null) {
        error.append(line);
        if (!line.endsWith(System.lineSeparator())) {
          error.append("\n");
        }
      }

      process.waitFor(30L, TimeUnit.SECONDS);

      return new ProcessExecOutput(output.toString(), error.toString(), process.exitValue());
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(
          String.format("Failed to execute command '%s' ", join(" ", cmdList)), e);
    }
  }

  public static class ProcessExecOutput {
    private final String output;
    private final String error;
    private final int exitCode;

    public ProcessExecOutput(String output, String error, int exitCode) {
      this.output = output;
      this.error = error;
      this.exitCode = exitCode;
    }

    public String getOutput() {
      return output;
    }

    public String getError() {
      return error;
    }

    public int getExitCode() {
      return exitCode;
    }
  }

  /**
   * Retrieves the executable path for a given command, verifying that it exists and can be executed
   * successfully.
   *
   * <p>This method uses {@link Operations#getCustomPathOrElse(String)} to obtain the path to the
   * executable for the specified command. It then attempts to run the executable with the
   * "--version" argument to verify that it is functional. If the executable is not found, cannot be
   * executed, or exits with a non-zero status code, a {@link RuntimeException} is thrown.
   *
   * @param command the name of the command (e.g., "mvn", "npm", "yarn") for which to find the
   *     executable
   * @return the path to the executable for the specified command
   * @throws RuntimeException if the executable cannot be found, is not executable, or exits with an
   *     error code
   */
  public static String getExecutable(
      String command, String args, final Map<String, String> envMap) {
    String cmdExecutable = Operations.getCustomPathOrElse(command);
    try {
      ProcessBuilder processBuilder = new ProcessBuilder();
      processBuilder.command(cmdExecutable, args);
      if (envMap != null) {
        processBuilder.environment().putAll(envMap);
      }
      Process process = processBuilder.start();

      int exitCode = process.waitFor();
      if (exitCode != 0) {
        throw new IOException(
            command + " executable found, but it exited with error code " + exitCode);
      }
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(
          String.format(
              "Unable to find or run "
                  + command
                  + " executable '%s'. Please ensure "
                  + command
                  + " is installed and"
                  + " available in your PATH.",
              cmdExecutable),
          e);
    }
    return cmdExecutable;
  }

  public static String getExecutable(String command, String args) {
    return getExecutable(command, args, null);
  }

  /**
   * Checks whether a wrapper preference is set for a given tool name.
   *
   * <p>This method looks for an environment variable with the name {@code
   * TRUSTIFY_DA_PREFER_<TOOLNAME>W}, where {@code <TOOLNAME>} is the uppercase form of the provided
   * {@code name} parameter. If the environment variable is present (i.e., not {@code null}), the
   * method returns {@code true}.
   *
   * @param name the tool name for which to check the wrapper preference (e.g., "maven", "gradle")
   * @return {@code true} if the corresponding environment variable is set; {@code false} otherwise
   */
  public static boolean getWrapperPreference(String name) {
    return Environment.get("TRUSTIFY_DA_PREFER_" + name.toUpperCase() + "W") != null;
  }

  /**
   * Retrieves a Maven configuration value from an environment variable.
   *
   * @param configName the configuration name (e.g., "USER_SETTINGS", "LOCAL_REPO")
   * @return the configuration value if set and not blank, null otherwise
   */
  public static String getMavenConfig(String configName) {
    String configValue = Environment.get("TRUSTIFY_DA_MVN_" + configName);
    return (configValue != null && !configValue.isBlank()) ? configValue : null;
  }

  /**
   * Attempts to retrieve the root directory of a Git repository for the given working directory.
   *
   * <p>This method runs the command {@code git rev-parse --show-toplevel} in the specified
   * directory, which returns the absolute path to the root of the current Git working tree. If the
   * command executes successfully and produces output, the trimmed result is returned as an {@link
   * Optional}. If the command fails or the output is empty, an empty {@code Optional} is returned.
   *
   * @param cwd the working directory in which to execute the Git command
   * @return an {@code Optional} containing the Git root directory path if found, otherwise {@code
   *     Optional.empty()}
   */
  public static Optional<String> getGitRootDir(String cwd) {
    List<String> command = Arrays.asList("git", "rev-parse", "--show-toplevel");
    ProcessBuilder builder =
        new ProcessBuilder(command).directory(new File(cwd)).redirectErrorStream(true);
    try {
      Process process = builder.start();
      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line = reader.readLine();
        int exitCode = process.waitFor();
        if (exitCode == 0) {
          return Optional.ofNullable(line).map(String::trim);
        } else {
          log.warning("Git command exited with code " + exitCode + " in directory " + cwd);
        }
      }
    } catch (IOException e) {
      log.warning("I/O error executing git in " + cwd + ": " + e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      log.warning("Git command interrupted in directory " + cwd + ": " + e.getMessage());
    }
    return Optional.empty();
  }

  public static boolean isWindows() {
    return System.getProperty("os.name").toLowerCase().contains("win");
  }
}
