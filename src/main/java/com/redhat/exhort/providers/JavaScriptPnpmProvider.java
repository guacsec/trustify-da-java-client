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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.redhat.exhort.tools.Ecosystem;
import com.redhat.exhort.tools.Operations;
import java.nio.file.Path;

/**
 * Concrete implementation of the {@link JavaScriptProvider} used for converting dependency trees
 * for pnpm projects (package.json) into a SBOM content for Stack analysis or Component analysis.
 */
public final class JavaScriptPnpmProvider extends JavaScriptProvider {

  public static final String LOCK_FILE = "pnpm-lock.yaml";
  public static final String CMD_NAME = Operations.isWindows() ? "pnpm.cmd" : "pnpm";

  public JavaScriptPnpmProvider(Path manifest) {
    super(manifest, Ecosystem.Type.PNPM, CMD_NAME);
  }

  @Override
  protected String lockFileName() {
    return LOCK_FILE;
  }

  @Override
  protected String[] updateLockFileCmd(Path manifestDir) {
    return new String[] {
      packageManager(), "install", "--frozen-lockfile", "--dir", manifestDir.toString()
    };
  }

  @Override
  protected String[] listDepsCmd(boolean includeTransitive, Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager(),
        "ls",
        "--dir",
        manifestDir.toString(),
        includeTransitive ? "--depth=Infinity" : "--depth=0",
        "--prod",
        "--json"
      };
    }
    return new String[] {
      packageManager(), "list", includeTransitive ? "--depth=-1" : "--depth=0", "--prod", "--json"
    };
  }

  @Override
  protected JsonNode buildDependencyTree(boolean includeTransitive) throws JsonProcessingException {
    var depTree = super.buildDependencyTree(includeTransitive);
    return depTree.get(0);
  }
}
