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
package io.github.guacsec.trustifyda.sbom;

import static io.github.guacsec.trustifyda.impl.ExhortApi.debugLoggingIsNeeded;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.utils.Environment;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;

public class CycloneDXSbom implements Sbom {

  private static final String TRUSTIFY_DA_IGNORE_METHOD = "TRUSTIFY_DA_IGNORE_METHOD";
  private final Logger log = LoggersFactory.getLogger(this.getClass().getName());
  private static final Version VERSION = Version.VERSION_14;
  private String exhortIgnoreMethod;
  private final Bom bom;
  private PackageURL root;

  private BiPredicate<Collection<?>, Component> belongingCriteriaBinaryAlgorithm;

  private <X, Y> Predicate<Y> genericComparator(
      BiPredicate<X, Y> binaryBelongingCriteriaAlgorithm, X container) {
    return dep -> binaryBelongingCriteriaAlgorithm.test(container, dep);
  }

  public CycloneDXSbom() {
    bom = new Bom();
    bom.setVersion(1);
    Metadata metadata = new Metadata();
    metadata.setTimestamp(new Date());
    bom.setMetadata(metadata);
    bom.setComponents(new ArrayList<>());
    bom.setDependencies(new ArrayList<>());
    belongingCriteriaBinaryAlgorithm = getBelongingConditionByName();
    this.exhortIgnoreMethod = "insensitive";
  }

  private static BiPredicate<Collection<?>, Component> getBelongingConditionByName() {
    return (collection, component) -> collection.contains(component.getName());
  }

  public CycloneDXSbom(BelongingCondition belongingCondition, String exhortIgnoreMethod) {
    this();
    if (belongingCondition.equals(BelongingCondition.NAME)) {
      belongingCriteriaBinaryAlgorithm = getBelongingConditionByName();
    } else if (belongingCondition.equals(BelongingCondition.PURL)) {
      belongingCriteriaBinaryAlgorithm = getBelongingConditionByPurl();
    } else {
      // fallback to belonging condition by name ( default) - this one in case the enum type will be
      // extended and
      // new BelongingType won't be implemented right away.
      belongingCriteriaBinaryAlgorithm = getBelongingConditionByName();
    }
    this.exhortIgnoreMethod = exhortIgnoreMethod;
  }

  private BiPredicate<Collection<?>, Component> getBelongingConditionByPurl() {
    return (collection, component) ->
        collection.contains(componentToPurl(component).getCoordinates());
  }

  /**
   * Creates a coordinate-based belonging condition that matches by groupId:artifactId only,
   * ignoring version. Used for handling dependencies with unresolved version properties.
   */
  private BiPredicate<Collection<?>, Component> getBelongingConditionByCoordinatesOnly() {
    return (collection, component) -> {
      PackageURL componentPurl = componentToPurl(component);
      String componentCoords = componentPurl.getNamespace() + ":" + componentPurl.getName();

      return collection.stream()
          .filter(String.class::isInstance)
          .map(String.class::cast)
          .anyMatch(
              ignoredPurlCoords -> {
                try {
                  PackageURL ignoredPurl = new PackageURL(ignoredPurlCoords);
                  String ignoredCoords = ignoredPurl.getNamespace() + ":" + ignoredPurl.getName();
                  return componentCoords.equals(ignoredCoords);
                } catch (MalformedPackageURLException e) {
                  return false;
                }
              });
    };
  }

  public Sbom addRoot(PackageURL rootRef) {
    this.root = rootRef;
    Component rootComponent = newRootComponent(rootRef);
    bom.getMetadata().setComponent(rootComponent);
    bom.getComponents().add(rootComponent);
    bom.getDependencies().add(newDependency(rootRef));
    return this;
  }

  public PackageURL getRoot() {
    return root;
  }

  @Override
  public <T> Sbom filterIgnoredDeps(Collection<T> ignoredDeps) {
    String exhortIgnoreMethod =
        Objects.requireNonNullElse(getExhortIgnoreMethod(), this.exhortIgnoreMethod);
    if (exhortIgnoreMethod.equals("insensitive")) {
      return filterIgnoredDepsInsensitive(ignoredDeps);
    } else {
      return filterIgnoredDepsSensitive(ignoredDeps);
    }
  }

  private String getExhortIgnoreMethod() {
    var val = Environment.get(TRUSTIFY_DA_IGNORE_METHOD);
    return val != null ? val.trim().toLowerCase() : null;
  }

  private Component newRootComponent(PackageURL ref) {
    Component c = new Component();
    c.setBomRef(ref.getCoordinates());
    c.setName(ref.getName());
    c.setGroup(ref.getNamespace());
    c.setVersion(ref.getVersion());
    c.setType(Type.APPLICATION);
    c.setPurl(ref);
    return c;
  }

  private Component newComponent(PackageURL ref, Component.Scope scope) {
    Component c = new Component();
    c.setBomRef(ref.getCoordinates());
    c.setName(ref.getName());
    c.setGroup(ref.getNamespace());
    c.setVersion(ref.getVersion());
    c.setPurl(ref);
    c.setType(Type.LIBRARY);
    if (scope != null) {
      c.setScope(scope);
    }
    return c;
  }

  private PackageURL componentToPurl(Component component) {
    try {
      return new PackageURL(component.getPurl());
    } catch (MalformedPackageURLException e) {
      throw new RuntimeException(e);
    }
  }

  private Dependency newDependency(PackageURL ref) {
    return new Dependency(ref.getCoordinates());
  }

  private <T> Sbom filterIgnoredDepsInsensitive(Collection<T> ignoredDeps) {

    List<String> initialIgnoreRefs =
        bom.getComponents().stream()
            .filter(
                c -> genericComparator(this.belongingCriteriaBinaryAlgorithm, ignoredDeps).test(c))
            .map(Component::getBomRef)
            .collect(Collectors.toList());
    List<String> refsToIgnore = createIgnoreFilter(bom.getDependencies(), initialIgnoreRefs);
    return removeIgnoredDepsFromSbom(refsToIgnore);
  }

  private Sbom removeIgnoredDepsFromSbom(List<String> refsToIgnore) {
    bom.setComponents(
        bom.getComponents().stream()
            .filter(c -> !refsToIgnore.contains(c.getBomRef()))
            .collect(Collectors.toList()));
    var newDeps =
        bom.getDependencies().stream()
            .filter(d -> !refsToIgnore.contains(d.getRef()))
            .collect(Collectors.toList());
    bom.setDependencies(newDeps);
    bom.getDependencies()
        .forEach(
            d -> {
              if (d.getDependencies() != null) {
                var filteredDeps =
                    d.getDependencies().stream()
                        .filter(td -> !refsToIgnore.contains(td.getRef()))
                        .collect(Collectors.toList());
                d.setDependencies(filteredDeps);
              }
            });
    return this;
  }

  private <T> Sbom filterIgnoredDepsSensitive(Collection<T> ignoredDeps) {

    List<String> refsToIgnore =
        bom.getComponents().stream()
            .filter(
                c -> genericComparator(this.belongingCriteriaBinaryAlgorithm, ignoredDeps).test(c))
            .map(Component::getBomRef)
            .collect(Collectors.toList());
    return removeIgnoredDepsFromSbom(refsToIgnore);
  }

  private List<String> createIgnoreFilter(List<Dependency> deps, Collection<String> toIgnore) {
    List<String> result = new ArrayList<>(toIgnore);
    for (Dependency dep : deps) {
      if (toIgnore.contains(dep.getRef()) && dep.getDependencies() != null) {
        List<String> collected =
            dep.getDependencies().stream().map(BomReference::getRef).collect(Collectors.toList());
        result.addAll(collected);
        if (dep.getDependencies().stream().anyMatch(Objects::nonNull)) {
          result = createIgnoreFilter(dep.getDependencies(), result);
        }
      }
    }
    return result;
  }

  @Override
  public Sbom addDependency(PackageURL sourceRef, PackageURL targetRef, String s) {
    Component.Scope scope = null;
    if (s != null) {
      scope = Component.Scope.valueOf(s.toUpperCase());
    }
    Component srcComp = newComponent(sourceRef, scope);
    Dependency srcDep;
    if (bom.getComponents().stream().noneMatch(c -> c.getBomRef().equals(srcComp.getBomRef()))) {
      bom.addComponent(srcComp);
      srcDep = newDependency(sourceRef);
      bom.addDependency(srcDep);
    } else {
      Optional<Dependency> existingDep =
          bom.getDependencies().stream()
              .filter(d -> d.getRef().equals(srcComp.getBomRef()))
              .findFirst();
      if (existingDep.isPresent()) {
        srcDep = existingDep.get();
      } else {
        srcDep = newDependency(sourceRef);
        bom.addDependency(srcDep);
      }
    }
    Dependency targetDep = newDependency(targetRef);
    srcDep.addDependency(targetDep);
    if (bom.getDependencies().stream().noneMatch(d -> d.getRef().equals(targetDep.getRef()))) {
      bom.addDependency(targetDep);
    }
    if (bom.getComponents().stream().noneMatch(c -> c.getBomRef().equals(targetDep.getRef()))) {
      bom.addComponent(newComponent(targetRef, scope));
    }
    return this;
  }

  @Override
  public String getAsJsonString() {
    try {
      var jsonString = BomGeneratorFactory.createJson(VERSION, bom).toJsonString();
      if (debugLoggingIsNeeded()) {
        log.info("Generated Sbom Json:" + System.lineSeparator() + jsonString);
      }
      return jsonString;
    } catch (GeneratorException e) {
      throw new RuntimeException("Unable to genenerate JSON from SBOM", e);
    }
  }

  @Override
  public void setBelongingCriteriaBinaryAlgorithm(BelongingCondition belongingCondition) {
    if (belongingCondition.equals(BelongingCondition.NAME)) {
      belongingCriteriaBinaryAlgorithm = getBelongingConditionByName();
    } else if (belongingCondition.equals(BelongingCondition.PURL)) {
      belongingCriteriaBinaryAlgorithm = getBelongingConditionByPurl();
    }
  }

  @Override
  public void setCoordinateBasedMatching() {
    belongingCriteriaBinaryAlgorithm = getBelongingConditionByCoordinatesOnly();
  }

  @Override
  public boolean checkIfPackageInsideDependsOnList(PackageURL component, String name) {
    boolean result = false;
    Optional<Dependency> comp =
        this.bom.getDependencies().stream()
            .filter(c -> c.getRef().equals(component.getCoordinates()))
            .findFirst();
    if (comp.isPresent()) {
      Dependency targetComponent = comp.get();
      List<Dependency> deps = targetComponent.getDependencies();
      List<PackageURL> allDirectDeps = Collections.emptyList();
      if (deps != null) {
        deps.stream()
            .map(
                dep -> {
                  try {
                    return new PackageURL(dep.getRef());
                  } catch (MalformedPackageURLException e) {
                    throw new RuntimeException(e);
                  }
                })
            .collect(Collectors.toList());
      }
      result = allDirectDeps.stream().anyMatch(dep -> dep.getName().equals(name));
    }
    return result;
  }

  @Override
  public void removeRootComponent() {
    bom.getComponents()
        .removeIf((component) -> component.getBomRef().equals(this.root.getCoordinates()));
    bom.getDependencies()
        .removeIf((dependency) -> dependency.getRef().equals(this.root.getCoordinates()));
    bom.getMetadata().setComponent(null);
  }
}
