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

import io.github.guacsec.trustifyda.image.ImageRef;
import java.nio.file.Path;
import java.util.Set;

public class CliArgs {
  public final Command command;
  public final Path filePath;
  public final Set<ImageRef> imageRefs;
  public final OutputFormat outputFormat;

  public CliArgs(Command command, Path filePath, OutputFormat outputFormat) {
    this.command = command;
    this.filePath = filePath;
    this.imageRefs = null;
    this.outputFormat = outputFormat;
  }

  public CliArgs(Command command, Set<ImageRef> imageRefs, OutputFormat outputFormat) {
    this.command = command;
    this.filePath = null;
    this.imageRefs = imageRefs;
    this.outputFormat = outputFormat;
  }
}
