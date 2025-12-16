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

import static io.github.guacsec.trustifyda.Provider.PROP_MATCH_MANIFEST_VERSIONS;
import static io.github.guacsec.trustifyda.impl.ExhortApi.debugLoggingIsNeeded;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.guacsec.trustifyda.exception.PackageNotInstalledException;
import io.github.guacsec.trustifyda.logging.LoggersFactory;
import io.github.guacsec.trustifyda.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class PythonControllerBase {

  public static final String PROP_TRUSTIFY_DA_PIP_PIPDEPTREE = "TRUSTIFY_DA_PIP_PIPDEPTREE";
  public static final String PROP_TRUSTIFY_DA_PIP_FREEZE = "TRUSTIFY_DA_PIP_FREEZE";
  public static final String PROP_TRUSTIFY_DA_PIP_USE_DEP_TREE = "TRUSTIFY_DA_PIP_USE_DEP_TREE";
  public static final String PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS =
      "TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS";
  public static final String PROP_TRUSTIFY_DA_PIP_SHOW = "TRUSTIFY_DA_PIP_SHOW";
  public static final String PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV = "TRUSTIFY_DA_PYTHON_VIRTUAL_ENV";

  private final Logger log = LoggersFactory.getLogger(this.getClass().getName());
  protected Path pythonEnvironmentDir;
  protected Path pipBinaryDir;

  protected String pathToPythonBin;

  protected String pipBinaryLocation;

  public abstract void prepareEnvironment(String pathToPythonBin);

  public abstract boolean automaticallyInstallPackageOnEnvironment();

  public abstract boolean isRealEnv();

  void installPackages(String pathToRequirements) {
    Operations.runProcess(pipBinaryLocation, "install", "-r", pathToRequirements);
    Operations.runProcess(pipBinaryLocation, "freeze");
  }

  public abstract boolean isVirtualEnv();

  public abstract void cleanEnvironment(boolean deleteEnvironment);

  public final List<Map<String, Object>> getDependencies(
      String pathToRequirements, boolean includeTransitive) {
    if (isVirtualEnv() || isRealEnv()) {
      prepareEnvironment(pathToPythonBin);
    }
    if (automaticallyInstallPackageOnEnvironment()) {
      boolean installBestEfforts =
          Environment.getBoolean(PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS, false);
      /*
       make best efforts to install the requirements.txt on the virtual environment created from
       the python3 passed in. that means that it will install the packages without referring to
       the versions, but will let pip choose the version tailored for version of the python
       environment( and of pip package manager) for each package.
      */
      if (installBestEfforts) {
        boolean matchManifestVersions = Environment.getBoolean(PROP_MATCH_MANIFEST_VERSIONS, true);
        if (matchManifestVersions) {
          throw new RuntimeException(
              "Conflicting settings, "
                  + PythonControllerBase.PROP_TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS
                  + "=true can only work with "
                  + PROP_MATCH_MANIFEST_VERSIONS
                  + "=false");
        } else {
          installingRequirementsOneByOne(pathToRequirements);
        }
      } else {
        installPackages(pathToRequirements);
      }
    }
    List<Map<String, Object>> dependencies =
        getDependenciesImpl(pathToRequirements, includeTransitive);
    if (isVirtualEnv()) {
      cleanEnvironment(false);
    }

    return dependencies;
  }

  private void installingRequirementsOneByOne(String pathToRequirements) {
    try {
      List<String> requirementsRows = Files.readAllLines(Path.of(pathToRequirements));
      requirementsRows.stream()
          .filter((line) -> !line.trim().startsWith("#"))
          .filter((line) -> !line.trim().isEmpty())
          .forEach(
              (dependency) -> {
                String dependencyName = getDependencyName(dependency);
                try {
                  Operations.runProcess(this.pipBinaryLocation, "install", dependencyName);
                } catch (RuntimeException e) {
                  throw new RuntimeException(
                      String.format(
                          "Best efforts process - failed installing package - %s in created virtual"
                              + " python environment --> error message got from underlying process"
                              + " => %s ",
                          dependencyName, e.getMessage()));
                }
              });

    } catch (IOException e) {
      throw new RuntimeException(
          "Cannot continue with analysis - error opening requirements.txt file in order to install"
              + " packages one by one in a best efforts manner - related error message => "
              + e.getMessage());
    }
  }

  private List<Map<String, Object>> getDependenciesImpl(
      String requirements, boolean includeTransitive) {
    List<Map<String, Object>> dependencies = new ArrayList<>();
    Map<StringInsensitive, PythonDependency> cachedEnvironmentDeps = new HashMap<>();
    fillCacheWithEnvironmentDeps(cachedEnvironmentDeps);
    var requirementsPath = Path.of(requirements);
    if (!Files.isRegularFile(requirementsPath)) {
      throw new IllegalArgumentException(
          "The requirements.txt file does not exist or is not a regular file: " + requirements);
    }
    List<String> linesOfRequirements;
    try {
      linesOfRequirements =
          Files.readAllLines(requirementsPath).stream()
              .filter((line) -> !line.trim().startsWith("#") && !line.trim().isEmpty())
              .map(String::trim)
              .collect(Collectors.toList());
    } catch (IOException e) {
      log.warning(
          "Error while trying to read the requirements.txt file, will not be able to install"
              + " packages one by one");
      throw new RuntimeException("Unable to read requirements.txt file: " + e.getMessage());
    }
    try {
      ObjectMapper om = new ObjectMapper();
      om.writerWithDefaultPrettyPrinter().writeValueAsString(cachedEnvironmentDeps);
    } catch (JsonProcessingException e) {
      log.warning(
          "Error while trying to convert the cached environment dependencies to JSON string");
      throw new RuntimeException(e);
    }
    boolean matchManifestVersions = Environment.getBoolean(PROP_MATCH_MANIFEST_VERSIONS, true);

    for (String dep : linesOfRequirements) {
      if (matchManifestVersions) {
        String dependencyName;
        String manifestVersion;
        String installedVersion = "";
        int doubleEqualSignPosition;
        if (dep.contains("==")) {
          doubleEqualSignPosition = dep.indexOf("==");
          manifestVersion = dep.substring(doubleEqualSignPosition + 2).trim();
          if (manifestVersion.contains("#")) {
            var hashCharIndex = manifestVersion.indexOf("#");
            manifestVersion = manifestVersion.substring(0, hashCharIndex);
          }
          dependencyName = getDependencyName(dep);
          PythonDependency pythonDependency =
              cachedEnvironmentDeps.get(new StringInsensitive(dependencyName));
          if (pythonDependency != null) {
            installedVersion = pythonDependency.getVersion();
          }
          if (!installedVersion.trim().isEmpty()) {
            if (!manifestVersion.trim().equals(installedVersion.trim())) {
              throw new RuntimeException(
                  String.format(
                      "Can't continue with analysis - versions mismatch for dependency"
                          + " name=%s, manifest version=%s, installed Version=%s, if you"
                          + " want to allow version mismatch for analysis between installed"
                          + " and requested packages, set environment variable/setting -"
                          + " %s=false",
                      dependencyName,
                      manifestVersion,
                      installedVersion,
                      PROP_MATCH_MANIFEST_VERSIONS));
            }
          }
        }
      }
      List<String> path = new ArrayList<>();
      String selectedDepName = getDependencyName(dep.toLowerCase());
      path.add(selectedDepName);
      bringAllDependencies(
          dependencies, selectedDepName, cachedEnvironmentDeps, includeTransitive, path);
    }

    return dependencies;
  }

  private String getPipShowFromEnvironment(List<String> depNames) {
    var args = new ArrayList<>();
    args.add(pipBinaryLocation);
    args.add("show");
    args.addAll(depNames);
    return executeCommandOrExtractFromEnv(PROP_TRUSTIFY_DA_PIP_SHOW, args.toArray(new String[] {}));
  }

  String getPipFreezeFromEnvironment() {
    return executeCommandOrExtractFromEnv(
        PROP_TRUSTIFY_DA_PIP_FREEZE, pipBinaryLocation, "freeze", "--all");
  }

  List<PythonDependency> getDependencyTreeJsonFromPipDepTree() {
    executeCommandOrExtractFromEnv(
        PROP_TRUSTIFY_DA_PIP_PIPDEPTREE, pipBinaryLocation, "install", "pipdeptree");

    String pipdeptreeJsonString = "";
    if (isVirtualEnv()) {
      pipdeptreeJsonString =
          executeCommandOrExtractFromEnv(
              PROP_TRUSTIFY_DA_PIP_PIPDEPTREE, "./bin/pipdeptree", "--json");
    } else if (isRealEnv()) {
      pipdeptreeJsonString =
          executeCommandOrExtractFromEnv(
              PROP_TRUSTIFY_DA_PIP_PIPDEPTREE, pathToPythonBin, "-m", "pipdeptree", "--json");
    }
    if (debugLoggingIsNeeded()) {
      String pipdeptreeMessage =
          String.format(
              "Package Manager pipdeptree --json command result output -> %s %s",
              System.lineSeparator(), pipdeptreeJsonString);
      log.info(pipdeptreeMessage);
    }
    return mapToPythonDependencies(pipdeptreeJsonString);
  }

  List<PythonDependency> mapToPythonDependencies(String jsonString) {
    try {
      // Parse JSON and store in a list of JsonNodes
      List<JsonNode> jsonNodeList = new ArrayList<>();
      new ObjectMapper().readTree(jsonString).elements().forEachRemaining(jsonNodeList::add);

      return jsonNodeList.stream()
          .filter(JsonNode::isObject)
          .map(
              dependencyNode -> {
                String name = dependencyNode.get("package").get("package_name").asText();
                String version = dependencyNode.get("package").get("installed_version").asText();

                // Extract dependencies
                List<String> depList = new ArrayList<>();
                dependencyNode
                    .get("dependencies")
                    .elements()
                    .forEachRemaining(e -> depList.add(e.get("package_name").asText()));

                return new PythonDependency(name, version, depList);
              })
          .collect(Collectors.toList());
    } catch (JsonProcessingException e) {
      throw new RuntimeException(
          "Could not parse the JSON output from 'pipdeptree --json' command. ", e);
    }
  }

  private String executeCommandOrExtractFromEnv(String EnvVar, String... cmdList) {
    String envValue = Environment.get(EnvVar, "");
    if (envValue.trim().isBlank())
      return Operations.runProcessGetOutput(pythonEnvironmentDir, cmdList);
    return new String(Base64.getDecoder().decode(envValue));
  }

  private void bringAllDependencies(
      List<Map<String, Object>> dependencyList,
      String depName,
      Map<StringInsensitive, PythonDependency> cachedTree,
      boolean includeTransitive,
      List<String> path) {

    if (dependencyList == null || depName.trim().isEmpty()) return;

    PythonDependency pythonDependency = cachedTree.get(new StringInsensitive(depName));
    if (pythonDependency == null) {
      throw new PackageNotInstalledException(
          String.format(
              "Package name=>%s is not installed on your python environment, either install it ("
                  + " better to install requirements.txt altogether) or turn on environment"
                  + " variable %s=true to automatically install it on"
                  + " virtual environment (will slow down the analysis)",
              depName, PROP_TRUSTIFY_DA_PYTHON_VIRTUAL_ENV));
    }

    Map<String, Object> dataMap = new HashMap<>();
    dataMap.put("name", pythonDependency.getName());
    dataMap.put("version", pythonDependency.getVersion());
    dependencyList.add(dataMap);

    List<Map<String, Object>> targetDeps = new ArrayList<>();
    List<String> directDeps = pythonDependency.getDependencies();
    for (String directDep : directDeps) {
      if (!path.contains(directDep.toLowerCase())) {
        List<String> depList = new ArrayList<>();
        depList.add(directDep.toLowerCase());

        if (includeTransitive) {
          bringAllDependencies(
              targetDeps,
              directDep,
              cachedTree,
              true,
              Stream.concat(path.stream(), depList.stream()).collect(Collectors.toList()));
        }
      }
      targetDeps.sort(
          (map1, map2) -> {
            String string1 = (String) (map1.get("name"));
            String string2 = (String) (map2.get("name"));
            return Arrays.compare(string1.toCharArray(), string2.toCharArray());
          });
      dataMap.put("dependencies", targetDeps);
    }
  }

  protected List<String> getDepsList(String pipShowOutput) {
    int requiresKeyIndex = pipShowOutput.indexOf("Requires:");
    String requiresToken = pipShowOutput.substring(requiresKeyIndex + 9);
    int endOfLine = requiresToken.indexOf(System.lineSeparator());
    String listOfDeps;
    if (endOfLine > -1) {
      listOfDeps = requiresToken.substring(0, endOfLine).trim();
    } else {
      listOfDeps = requiresToken;
    }
    return Arrays.stream(listOfDeps.split(","))
        .map(String::trim)
        .filter(dep -> !dep.isEmpty())
        .collect(Collectors.toList());
  }

  protected String getDependencyVersion(String pipShowOutput) {
    int versionKeyIndex = pipShowOutput.indexOf("Version:");
    String versionToken = pipShowOutput.substring(versionKeyIndex + 8);
    int endOfLine = versionToken.indexOf(System.lineSeparator());
    return versionToken.substring(0, endOfLine).trim();
  }

  protected String getDependencyNameShow(String pipShowOutput) {
    int versionKeyIndex = pipShowOutput.indexOf("Name:");
    String versionToken = pipShowOutput.substring(versionKeyIndex + 5);
    int endOfLine = versionToken.indexOf(System.lineSeparator());
    return versionToken.substring(0, endOfLine).trim();
  }

  public static String getDependencyName(String dep) {
    int rightTriangleBracket = dep.indexOf(">");
    int leftTriangleBracket = dep.indexOf("<");
    int equalsSign = dep.indexOf("=");
    int minimumIndex = getFirstSign(rightTriangleBracket, leftTriangleBracket, equalsSign);
    String depName;
    if (rightTriangleBracket == -1 && leftTriangleBracket == -1 && equalsSign == -1) {
      depName = dep;
    } else {
      depName = dep.substring(0, minimumIndex);
    }
    return depName.trim();
  }

  private static int getFirstSign(
      int rightTriangleBracket, int leftTriangleBracket, int equalsSign) {
    rightTriangleBracket = rightTriangleBracket == -1 ? 999 : rightTriangleBracket;
    leftTriangleBracket = leftTriangleBracket == -1 ? 999 : leftTriangleBracket;
    equalsSign = equalsSign == -1 ? 999 : equalsSign;
    return equalsSign < leftTriangleBracket && equalsSign < rightTriangleBracket
        ? equalsSign
        : (leftTriangleBracket < equalsSign && leftTriangleBracket < rightTriangleBracket
            ? leftTriangleBracket
            : rightTriangleBracket);
  }

  static List<String> splitPipShowLines(String pipShowOutput) {
    return Arrays.stream(
            pipShowOutput.split(System.lineSeparator() + "---" + System.lineSeparator()))
        .collect(Collectors.toList());
  }

  private PythonDependency getPythonDependencyByShowStringBlock(String pipShowStringBlock) {
    return new PythonDependency(
        getDependencyNameShow(pipShowStringBlock),
        getDependencyVersion(pipShowStringBlock),
        getDepsList(pipShowStringBlock));
  }

  private void fillCacheWithEnvironmentDeps(Map<StringInsensitive, PythonDependency> cache) {
    boolean usePipDepTree = Environment.getBoolean(PROP_TRUSTIFY_DA_PIP_USE_DEP_TREE, false);
    if (usePipDepTree) {
      getDependencyTreeJsonFromPipDepTree().forEach(d -> saveToCacheWithKeyVariations(cache, d));
    } else {
      String freezeOutput = getPipFreezeFromEnvironment();
      if (debugLoggingIsNeeded()) {
        String freezeMessage =
            String.format(
                "Package Manager PIP freeze --all command result output -> %s %s",
                System.lineSeparator(), freezeOutput);
        log.info(freezeMessage);
      }
      String[] deps = freezeOutput.split(System.lineSeparator());
      var depNames =
          Arrays.stream(deps)
              .filter(line -> !line.contains("@ file"))
              .map(PythonControllerBase::getDependencyName)
              .collect(Collectors.toList());
      String pipShowOutput = getPipShowFromEnvironment(depNames);
      if (debugLoggingIsNeeded()) {
        String pipShowMessage =
            String.format(
                "Package Manager PIP show command result output -> %s %s",
                System.lineSeparator(), pipShowOutput);
        log.info(pipShowMessage);
      }
      splitPipShowLines(pipShowOutput).stream()
          .map(this::getPythonDependencyByShowStringBlock)
          .forEach(d -> saveToCacheWithKeyVariations(cache, d));
    }
  }

  private void saveToCacheWithKeyVariations(
      Map<StringInsensitive, PythonDependency> cache, PythonDependency pythonDependency) {
    StringInsensitive stringInsensitive = new StringInsensitive(pythonDependency.getName());
    cache.put(stringInsensitive, pythonDependency);
    cache.putIfAbsent(
        new StringInsensitive(pythonDependency.getName().replace("-", "_")), pythonDependency);
    cache.putIfAbsent(
        new StringInsensitive(pythonDependency.getName().replace("_", "-")), pythonDependency);
  }
}
