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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatRuntimeException;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;

class Operations_Test {
  @Nested
  class Test_runProcess {
    @Test
    void when_running_process_for_existing_command_should_not_throw_exception() {
      assertThatNoException().isThrownBy(() -> Operations.runProcess("ls", "."));
    }

    @Test
    void when_running_process_for_non_existing_command_should_throw_runtime_exception() {
      assertThatRuntimeException().isThrownBy(() -> Operations.runProcess("unknown", "--command"));
    }
  }

  @Nested
  class Test_getCustomPathOrElse {

    @Test
    @SetSystemProperty(key = "EXHORT_MADE_UP_CMD_PATH", value = "/path/to/made_up_cmd")
    void when_custom_path_exists_as_property() {
      assertThat(Operations.getCustomPathOrElse("made-up cmd")).isEqualTo("/path/to/made_up_cmd");
    }

    @Test
    void when_no_custom_path_in_env_var_or_properties_should_return_the_default_executable() {
      assertThat(Operations.getCustomPathOrElse("madeupcmd")).isEqualTo("madeupcmd");
    }
  }
}
