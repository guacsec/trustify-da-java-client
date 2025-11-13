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
package com.redhat.exhort.vcs;

import com.redhat.exhort.tools.Operations;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.regex.Pattern;

public class GitVersionControlSystemImpl implements VersionControlSystem {

  private final String gitBinary;

  public GitVersionControlSystemImpl() {
    gitBinary = Operations.getCustomPathOrElse("git");
  }

  @Override
  public TagInfo getLatestTag(Path repoLocation) {
    TagInfo tagInfo = new TagInfo();

    // get current commit hash digest
    String commitHash =
        Operations.runProcessGetOutput(repoLocation, gitBinary, "rev-parse", "HEAD").trim();
    if (Pattern.matches("^[a-f0-9]+", commitHash)) {
      tagInfo.setCurrentCommitDigest(commitHash);
      // get current commit timestamp.
      String timeStampFromGit =
          Operations.runProcessGetOutput(
              repoLocation,
              gitBinary,
              "show",
              "HEAD",
              "--format=%cI",
              "--date",
              "local",
              "--quiet");
      LocalDateTime commitTimestamp =
          LocalDateTime.parse(timeStampFromGit.trim(), DateTimeFormatter.ISO_OFFSET_DATE_TIME);
      tagInfo.setCommitTimestamp(commitTimestamp);

      // go get last annotated tag
      String resultFromInvocation =
          Operations.runProcessGetOutput(repoLocation, gitBinary, "describe", "--abbrev=12").trim();

      // if there are only unannotated tag, fetch last one.
      if (resultFromInvocation.contains("there were unannotated tags")) {
        // fetch last unannotated tag
        resultFromInvocation =
            Operations.runProcessGetOutput(
                    repoLocation, gitBinary, "describe", "--tags", "--abbrev=12")
                .trim();
        fetchLatestTag(tagInfo, resultFromInvocation);
      } else {
        if (resultFromInvocation.startsWith("fatal: No names found")) {
          tagInfo.setCurrentCommitPointedByTag(false);
          tagInfo.setTagName("");
        }
        // fetch last annotated tag
        else {
          fetchLatestTag(tagInfo, resultFromInvocation);
        }
      }
    }

    // empty git repo with no commits
    else {
      tagInfo.setTagName("");
      tagInfo.setCurrentCommitPointedByTag(false);
      tagInfo.setCommitTimestamp(
          LocalDateTime.parse(LocalDateTime.MIN.toString(), DateTimeFormatter.ISO_LOCAL_DATE_TIME));
      tagInfo.setCurrentCommitDigest("");
    }
    return tagInfo;
  }

  @Override
  public boolean isDirectoryRepo(Path repoLocation) {
    try {
      String resultFromInvocation =
          Operations.runProcessGetOutput(
              repoLocation, gitBinary, "rev-parse", "--is-inside-work-tree");
      return resultFromInvocation.trim().equals("true");
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  public String getNextTagVersion(TagInfo tagInfo) {
    String result = "";
    // if tag version ends with a digit, then increment it by one, and append to the end -0.
    if (Pattern.matches(".*[0-9]$", tagInfo.getTagName())) {
      int length = tagInfo.getTagName().length();
      Integer lastDigit = Integer.parseInt(tagInfo.getTagName().substring(length - 1, length));
      lastDigit++;
      result = String.format("%s%s-0", tagInfo.getTagName().substring(0, length - 1), lastDigit);
    } else {
      // if tag version ends with some suffix starting with '.' or '-', then just append to the end
      // -0.
      if (Pattern.matches(".*-[a-zA-Z0-9]+$|.*\\.[a-zA-Z0-9]+$", tagInfo.getTagName())) {
        result = String.format("%s-0", tagInfo.getTagName());
      }
    }
    return result;
  }

  public String getPseudoVersion(TagInfo tagInfo, String newTagVersion) {
    String stringTS =
        tagInfo.getCommitTimestamp().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
    String commitHash12 = tagInfo.getCurrentCommitDigest().substring(0, 12);
    return String.format("%s.%s-%s", newTagVersion, stringTS, commitHash12);
  }

  private static void fetchLatestTag(TagInfo tagInfo, String resultFromInvocation) {
    String[] parts = resultFromInvocation.split("-");
    if (parts.length > 1) {
      analyzeGitDescribeResult(tagInfo, parts);

    } else {
      tagInfo.setCurrentCommitPointedByTag(true);
      tagInfo.setTagName(parts[0]);
    }
  }

  private static void analyzeGitDescribeResult(TagInfo tagInfo, String[] parts) {
    if (Pattern.matches("g[0-9a-f]{12}", parts[parts.length - 1])
        && Pattern.matches("[1-9]*", parts[parts.length - 2])) {
      String[] tagNameParts = Arrays.copyOfRange(parts, 0, parts.length - 2);
      tagInfo.setTagName(String.join("-", tagNameParts));
      tagInfo.setCurrentCommitDigest(parts[parts.length - 1].replace("g", ""));
      tagInfo.setCurrentCommitPointedByTag(false);
    } else {
      String[] tagNameParts = Arrays.copyOfRange(parts, 0, parts.length - 2);
      tagInfo.setTagName(String.join("-", tagNameParts));
      tagInfo.setCurrentCommitPointedByTag(true);
    }
  }
}
