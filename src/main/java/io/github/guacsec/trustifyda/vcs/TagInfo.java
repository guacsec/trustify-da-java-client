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
package io.github.guacsec.trustifyda.vcs;

import java.time.LocalDateTime;

public class TagInfo {

  private String tagName;
  private boolean currentCommitPointedByTag;
  private String currentCommitDigest;

  public LocalDateTime getCommitTimestamp() {
    return commitTimestamp;
  }

  public void setCommitTimestamp(LocalDateTime commitTimestamp) {
    this.commitTimestamp = commitTimestamp;
  }

  private LocalDateTime commitTimestamp;

  public String getTagName() {
    return tagName;
  }

  public void setTagName(String tagName) {
    this.tagName = tagName;
  }

  public boolean isCurrentCommitPointedByTag() {
    return currentCommitPointedByTag;
  }

  public void setCurrentCommitPointedByTag(boolean currentCommitPointedByTag) {
    this.currentCommitPointedByTag = currentCommitPointedByTag;
  }

  public String getCurrentCommitDigest() {
    return currentCommitDigest;
  }

  public void setCurrentCommitDigest(String currentCommitDigest) {
    this.currentCommitDigest = currentCommitDigest;
  }
}
