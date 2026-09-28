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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatRuntimeException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OperationsTest {

  @TempDir Path tempDir;

  @Test
  void when_running_process_for_existing_command_should_not_throw_exception() {
    assertThatNoException().isThrownBy(() -> Operations.runProcess("ls", "."));
  }

  @Test
  void when_running_process_for_non_existing_command_should_throw_runtime_exception() {
    assertThatRuntimeException().isThrownBy(() -> Operations.runProcess("unknown", "--command"));
  }

  @Test
  void timed_out_process_kills_descendants() throws Exception {
    Path marker = tempDir.resolve("child-output");
    String[] command = {
      "sh",
      "-c",
      "(while :; do echo tick >> \"$1\"; sleep .1; done) & wait",
      "sh",
      marker.toString()
    };

    assertThatRuntimeException()
        .isThrownBy(() -> Operations.runProcess(null, command, null, 1))
        .withMessageContaining("timed out");
    assertThat(Files.readString(marker)).isNotEmpty();
    String output = Files.readString(marker);
    Thread.sleep(300);
    assertThat(Files.readString(marker)).isEqualTo(output);
  }

  @Test
  void interrupted_output_collection_preserves_interrupt() throws Exception {
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicBoolean interrupted = new AtomicBoolean();
    Thread caller =
        Thread.ofVirtual()
            .start(
                () -> {
                  try {
                    Operations.runProcess("sh", "-c", "sleep 2 & exit 7");
                  } catch (Throwable e) {
                    failure.set(e);
                    interrupted.set(Thread.currentThread().isInterrupted());
                  }
                });
    Thread.sleep(300);
    caller.interrupt();
    caller.join(10000);

    assertThat(caller.isAlive()).isFalse();
    assertThat(failure.get())
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("interrupted");
    assertThat(interrupted.get()).isTrue();
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
