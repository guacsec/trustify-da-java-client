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
package io.github.guacsec.trustifyda.utils;

import java.nio.file.FileSystems;
import java.nio.file.Path;

public class PythonControllerRealEnv extends PythonControllerBase {
  public PythonControllerRealEnv(String pathToPythonBin, String pathToPip) {
    Path pipPath = Path.of(pathToPip);
    this.pipBinaryDir = pipPath.getParent();
    if (this.pipBinaryDir == null) {
      this.pipBinaryDir = pipPath;
    }
    this.pythonEnvironmentDir = Path.of(Environment.get("user.dir"));
    this.pathToPythonBin = pathToPythonBin;
  }

  @Override
  public void prepareEnvironment(String pathToPythonBin) {
    String envBinDir = pipBinaryDir.toString();
    if (envBinDir.contains(FileSystems.getDefault().getSeparator())) {
      if (pathToPythonBin.contains("python3")) {
        this.pipBinaryLocation = Path.of(envBinDir, "pip3").toString();
      } else {
        this.pipBinaryLocation = Path.of(envBinDir, "pip").toString();
      }
    } else {
      this.pipBinaryLocation = envBinDir;
    }
  }

  @Override
  public boolean automaticallyInstallPackageOnEnvironment() {
    return false;
  }

  @Override
  public boolean isRealEnv() {
    return true;
  }

  @Override
  public boolean isVirtualEnv() {
    return false;
  }

  @Override
  public void cleanEnvironment(boolean cleanEnvironment) {

    // noop as this is real environment,
  }
}
