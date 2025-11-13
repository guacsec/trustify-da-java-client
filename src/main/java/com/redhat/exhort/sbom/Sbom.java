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
package com.redhat.exhort.sbom;

import com.github.packageurl.PackageURL;
import java.util.Collection;

public interface Sbom {

  public Sbom addRoot(PackageURL root);

  public PackageURL getRoot();

  public <T> Sbom filterIgnoredDeps(Collection<T> ignoredDeps);

  public Sbom addDependency(PackageURL sourceRef, PackageURL targetRef, String scope);

  public String getAsJsonString();

  public void setBelongingCriteriaBinaryAlgorithm(BelongingCondition belongingCondition);

  public boolean checkIfPackageInsideDependsOnList(PackageURL component, String name);

  void removeRootComponent();

  public enum BelongingCondition {
    NAME("name"),
    PURL("purl");

    String belongingCondition;

    BelongingCondition(String belongingCondition) {
      this.belongingCondition = belongingCondition;
    }

    public String getBelongingCondition() {
      return belongingCondition;
    }
  }
}
