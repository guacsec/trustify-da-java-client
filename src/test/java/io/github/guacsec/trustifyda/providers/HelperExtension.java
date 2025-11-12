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
package io.github.guacsec.trustifyda.providers;

import io.github.guacsec.trustifyda.impl.ExhortApi;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import java.util.logging.Logger;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class HelperExtension
    implements BeforeAllCallback, AfterAllCallback, BeforeEachCallback, AfterEachCallback {

  private static final Logger LOG = LoggersFactory.getLogger(ExhortApi.class.getName());

  @Override
  public void afterAll(ExtensionContext extensionContext) {
    LOG.info("Finished all tests!!");
  }

  @Override
  public void afterEach(ExtensionContext extensionContext) {
    LOG.info(
        String.format(
            "Finished Test Method: %s_%s",
            extensionContext.getRequiredTestMethod().getName(), extensionContext.getDisplayName()));
  }

  @Override
  public void beforeAll(ExtensionContext extensionContext) {

    LOG.info("Before all tests");
  }

  @Override
  public void beforeEach(ExtensionContext extensionContext) {
    LOG.info(
        String.format(
            "Started Test Method: %s_%s",
            extensionContext.getRequiredTestMethod().getName(), extensionContext.getDisplayName()));
  }
}
