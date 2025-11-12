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
package io.github.guacsec.trustifyda.logging;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.guacsec.trustifyda.impl.RequestManager;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;

public class ClientTraceIdSimpleFormatter extends SimpleFormatter {

  private final ObjectMapper objectMapper;

  public ClientTraceIdSimpleFormatter() {
    this.objectMapper = new ObjectMapper();
    this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
  }

  @Override
  public String format(LogRecord record) {
    Map<String, Object> messageKeysValues = new HashMap<>();
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    ZonedDateTime zdt = ZonedDateTime.ofInstant(record.getInstant(), ZoneId.systemDefault());
    String source;
    if (record.getSourceClassName() != null) {
      source = record.getSourceClassName();
      if (record.getSourceMethodName() != null) {
        source += " " + record.getSourceMethodName();
      }
    } else {
      source = record.getLoggerName();
    }
    String message = formatMessage(record);
    if (record.getThrown() != null) {
      StringWriter sw = new StringWriter();
      PrintWriter pw = new PrintWriter(sw);
      pw.println();
      record.getThrown().printStackTrace(pw);
      pw.close();
    }

    messageKeysValues.put("timestamp", zdt.toString());
    messageKeysValues.put("ex-client-trace-id", RequestManager.getInstance().getTraceIdOfRequest());
    messageKeysValues.put("methodName", source);
    messageKeysValues.put("loggerName", record.getLoggerName());
    messageKeysValues.put("logLevel", record.getLevel().toString());
    messageKeysValues.put("threadName", Thread.currentThread().getName());
    messageKeysValues.put("threadId", Thread.currentThread().getId());
    String jsonPartOfMessage = getJsonPartOfMessage(message);
    if (isValidJson(jsonPartOfMessage) || messageContainsOutputStructure(message)) {
      messageKeysValues.put(
          "logMessage",
          "log Message Contains a structure , and it will follow after the log entry");
    } else {
      messageKeysValues.put("logMessage", message);
    }
    try {
      String jsonLogRecord =
          objectMapper.writeValueAsString(messageKeysValues) + System.lineSeparator();
      return jsonLogRecord + suffixRequired(messageKeysValues, message);
    } catch (JsonProcessingException e) {
      return String.format(
          "%s, ex-client-trace-id: %s",
          super.format(record).trim(),
          RequestManager.getInstance().getTraceIdOfRequest() + System.lineSeparator());
    }
  }

  private String suffixRequired(Map<String, Object> messageKeysValues, String message) {
    if (((String) messageKeysValues.get("logMessage"))
        .trim()
        .contains("log Message Contains a structure")) {
      return message.trim() + System.lineSeparator();
    } else {
      return "";
    }
  }

  private boolean messageContainsOutputStructure(String message) {
    String messageWithLC = message.toLowerCase();
    return messageWithLC.contains("package manager") && messageWithLC.contains("output");
  }

  private boolean isValidJson(String jsonPartOfMessage) {
    if (Objects.isNull(jsonPartOfMessage)) {
      return false;
    }
    try {
      objectMapper.readTree(jsonPartOfMessage);
    } catch (JacksonException e) {
      return false;
    }
    return true;
  }

  private String getJsonPartOfMessage(String message) {
    int startOfJson = message.indexOf("{");
    int endOfJson = message.lastIndexOf("}");
    if (startOfJson > -1 && endOfJson > 0) {
      return message.substring(startOfJson, endOfJson + 1);
    } else {
      return null;
    }
  }
}
