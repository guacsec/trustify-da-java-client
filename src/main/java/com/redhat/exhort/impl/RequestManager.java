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
package com.redhat.exhort.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class RequestManager {

  private static RequestManager requestManager;
  private final Map<String, String> requests;

  public static RequestManager getInstance() {
    if (Objects.isNull(requestManager)) {
      requestManager = new RequestManager();
    }
    return requestManager;
  }

  private RequestManager() {
    requests = new HashMap<>();
  }

  public synchronized void addClientTraceIdToRequest(String requestId) {
    requests.put(concatenatedThreadId(), requestId);
  }

  public synchronized void removeClientTraceIdFromRequest() {
    String removedClientTraceId = requests.remove(concatenatedThreadId());
    // remove the traceId If it was propagated from parent Thread.
    if (removedClientTraceId != null) {
      Optional<String> keyOfParent =
          requests.entrySet().stream()
              .filter(pair -> pair.getValue().equals(removedClientTraceId))
              .map(Map.Entry::getKey)
              .findFirst();
      keyOfParent.ifPresent(requests::remove);
    }
  }

  public String getTraceIdOfRequest() {
    return requests.get(concatenatedThreadId());
  }

  private static String concatenatedThreadId() {
    return String.format("%s-%s", Thread.currentThread().getName(), Thread.currentThread().getId());
  }
}
