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
package io.github.guacsec.trustifyda;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import org.apache.commons.io.FileUtils;

public class ExhortTest {

  protected String getStringFromFile(String path) {
    byte[] bytes;
    try {
      InputStream resourceAsStream = getResourceAsStreamDecision(this.getClass(), path);
      bytes = resourceAsStream.readAllBytes();
      resourceAsStream.close();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    return new String(bytes);
  }

  public static InputStream getResourceAsStreamDecision(Class<?> theClass, String path)
      throws IOException {
    InputStream resourceAsStreamFromModule = theClass.getModule().getResourceAsStream(path);
    if (Objects.isNull(resourceAsStreamFromModule)) {
      return theClass.getClassLoader().getResourceAsStream(path);
    }
    return resourceAsStreamFromModule;
  }

  public static Path resolveFile(String path) {
    return Path.of("src/test/resources", path);
  }

  protected String getFileFromResource(String fileName, String path) {
    Path tmpFile;
    try {
      var tmpDir = Files.createTempDirectory("TRUSTIFY_DA_test_");
      tmpFile = Files.createFile(tmpDir.resolve(fileName));
      try (var is = getResourceAsStreamDecision(this.getClass(), path)) {
        if (Objects.nonNull(is)) {
          Files.write(tmpFile, is.readAllBytes());
        } else {
          InputStream resourceIs = getClass().getClassLoader().getResourceAsStream(path);
          Files.write(tmpFile, resourceIs.readAllBytes());
          resourceIs.close();
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return tmpFile.toString();
  }

  public static class TempDirFromResources {
    private final Path tmpDir;

    public TempDirFromResources() throws IOException {
      tmpDir = Files.createTempDirectory("TRUSTIFY_DA_test_");
    }

    public class AddPath {
      private final String fileName;

      public AddPath(String fileName) {
        this.fileName = fileName;
      }

      public TempDirFromResources fromResources(String path) {
        Path tmpFile;
        try {
          tmpFile = Files.createFile(tmpDir.resolve(this.fileName));
          try (var is = getResourceAsStreamDecision(super.getClass(), path)) {
            if (Objects.nonNull(is)) {
              Files.write(tmpFile, is.readAllBytes());
            } else {
              InputStream resourceIs = getClass().getClassLoader().getResourceAsStream(path);
              Files.write(tmpFile, resourceIs.readAllBytes());
              resourceIs.close();
            }
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        return TempDirFromResources.this;
      }
    }

    public AddPath addFile(String fileName) {
      return new AddPath(fileName);
    }

    public TempDirFromResources addDirectory(String dirName, String path) {
      File target = this.tmpDir.resolve(dirName).toFile();
      URL resource = this.getClass().getClassLoader().getResource(path);
      File source = new File(Objects.requireNonNull(resource).getFile());
      try {
        FileUtils.copyDirectory(source, target);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      return this;
    }

    public TempDirFromResources addFile(Optional<String> fileName, Supplier<String> path) {
      if (fileName.isEmpty()) {
        return this;
      }

      return new AddPath(fileName.get()).fromResources(path.get());
    }

    public Path getTempDir() {
      return this.tmpDir;
    }
  }

  protected String getFileFromString(String fileName, String content) {
    Path tmpFile;
    try {
      var tmpDir = Files.createTempDirectory("TRUSTIFY_DA_test_");
      tmpFile = Files.createFile(tmpDir.resolve(fileName));
      Files.write(tmpFile, content.getBytes());

    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return tmpFile.toString();
  }
}
