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
package com.redhat.exhort.logging;

import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

public class LoggersFactory {
  public static Logger getLogger(String loggerName) {
    Logger logger = Logger.getLogger(loggerName);
    if (logger.getHandlers().length == 0) {
      ConsoleHandler handler = new ConsoleHandler();
      handler.setFormatter(new ClientTraceIdSimpleFormatter());
      logger.addHandler(handler);
    }
    logger.setUseParentHandlers(false);
    return logger;
  }
}
