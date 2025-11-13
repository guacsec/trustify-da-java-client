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
package com.redhat.exhort.tools;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatRuntimeException;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class OperationsTest {

  @Test
  void when_running_process_for_existing_command_should_not_throw_exception() {
    assertThatNoException().isThrownBy(() -> Operations.runProcess("ls", "."));
  }

  @Test
  void when_running_process_for_non_existing_command_should_throw_runtime_exception() {
    assertThatRuntimeException().isThrownBy(() -> Operations.runProcess("unknown", "--command"));
  }

  @Test
  void when_running_process_get_full_output_for_existing_command_should_not_throw_exception() {
    assertThatNoException()
        .isThrownBy(() -> Operations.runProcessGetFullOutput(null, new String[] {"ls", "."}, null));
  }

  @Test
  void
      when_running_process_get_full_output_for_non_existing_command_should_throw_runtime_exception() {
    assertThatRuntimeException()
        .isThrownBy(
            () ->
                Operations.runProcessGetFullOutput(
                    Path.of("."),
                    new String[] {"unknown", "--command"},
                    new String[] {"PATH=123"}));
  }
}
