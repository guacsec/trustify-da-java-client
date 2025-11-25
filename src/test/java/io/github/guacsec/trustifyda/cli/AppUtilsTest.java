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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AppUtilsTest {

  @Test
  void printLine_with_message_should_print_to_stdout() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    PrintStream originalOut = System.out;
    System.setOut(new PrintStream(outputStream));

    try {
      AppUtils.printLine("Test message");
      assertThat(outputStream.toString()).isEqualTo("Test message" + System.lineSeparator());
    } finally {
      System.setOut(originalOut);
    }
  }

  @Test
  void printLine_without_message_should_print_empty_line() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    PrintStream originalOut = System.out;
    System.setOut(new PrintStream(outputStream));

    try {
      AppUtils.printLine();
      assertThat(outputStream.toString()).isEqualTo(System.lineSeparator());
    } finally {
      System.setOut(originalOut);
    }
  }

  @Test
  void printError_should_print_to_stderr() {
    ByteArrayOutputStream errorStream = new ByteArrayOutputStream();
    PrintStream originalErr = System.err;
    System.setErr(new PrintStream(errorStream));

    try {
      AppUtils.printError("Error message");
      String expected = "Error message" + System.lineSeparator() + System.lineSeparator();
      assertThat(errorStream.toString()).isEqualTo(expected);
    } finally {
      System.setErr(originalErr);
    }
  }

  @Test
  void printException_should_print_formatted_error() {
    ByteArrayOutputStream errorStream = new ByteArrayOutputStream();
    PrintStream originalErr = System.err;
    System.setErr(new PrintStream(errorStream));

    try {
      Exception testException = new RuntimeException("Test exception message");
      AppUtils.printException(testException);

      String expected =
          "Error: Test exception message" + System.lineSeparator() + System.lineSeparator();
      assertThat(errorStream.toString()).isEqualTo(expected);
    } finally {
      System.setErr(originalErr);
    }
  }

  @Test
  void exitWithError_should_be_callable() {
    // Note: We cannot easily test System.exit(1) call without actually exiting
    // This test ensures the method is callable and accessible
    // The actual System.exit behavior would need to be tested with SecurityManager
    // or process-level testing, which is beyond unit test scope
    try {
      // We can't actually call exitWithError() as it would terminate the JVM
      // Just verify the method exists and is accessible
      assertThat(AppUtils.class.getMethod("exitWithError")).isNotNull();
    } catch (NoSuchMethodException e) {
      throw new AssertionError("exitWithError method should exist", e);
    }
  }
}
