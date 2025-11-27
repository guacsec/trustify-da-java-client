# Trustify DA Java Client<br/>![latest-no-snapshot][0] ![latest-snapshot][1]

* Looking for our JavaScript/TypeScript API? Try [Trustify DA JavaScript Client](https://github.com/guacsec/trustify-da-javascript-client).
* Looking for our Backend implementation? Try [Trustify Dependency Analytics](https://github.com/guacsec/trustify-dependency-analytics).

The _Trustify DA Java Client_ module is deployed to _GitHub Package Registry_.

<details>
<summary>Click here for configuring <em>GHPR</em> registry access.</summary>
<h3>Configure Registry Access</h3>
<p>
Create a
<a href="https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages#authenticating-to-github-packages">token</a>
with the <strong>read:packages</strong> scope<br/>

> Based on
> <a href="https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry">GitHub documentation</a>,
> In <em>Actions</em> you can use <em>GITHUB_TOKEN</em>
</p>

<ul>
<li>
<p><em>Maven</em> users</p>
<ol>
<li>Encrypt your token

```shell
$ mvn --encrypt-password your-ghp-token-goes-here

encrypted-token-will-appear-here
```
</li>
<li>Add a <em>server</em> definition in your <em>$HOME/.m2/settings.xml</em>

```xml
<servers>
    <!-- ... other servers -->
    <server>
        <id>github</id>
        <username>github-userid-goes-here</username>
        <password>encrypted-token-goes-here-including-curly-brackets</password>
    </server>
    <!-- ... other servers -->
</servers>
```
</li>
</ol>
</li>

<li>
<em>Gradle</em> users, save your token and username as environment variables
<ul>
<li><em>GITHUB_USERNAME</em></li>
<li><em>GITHUB_TOKEN</em></li>
</ul>
</li>
</ul>
</details>

<h3>Usage</h3>
<ol>
<li>Configure Registry</li>
<ul>
<li>
<em>Maven</em> users, add a <em>repository</em> definition in <em>pom.xml</em>

```xml
  <repositories>
    <!-- ... other repositories -->
    <repository>
      <id>github</id>
      <url>https://maven.pkg.github.com/guacsec/trustify-da-java-client</url>
    </repository>
    <!-- ... other repositories -->
  </repositories>
```
</li>

<li>
<em>Gradle</em> users, add a <em>maven-type repository</em> definition in <em>build.gradle</em> (Groovy DSL) or <em>build.gradle.kts</em> (Kotlin DSL)

```groovy
repositories {
    // ... other repositories
    maven {
        url 'https://maven.pkg.github.com/guacsec/trustify-da-java-client'
        credentials {
            username System.getenv("GITHUB_USERNAME")
            password System.getenv("GITHUB_TOKEN")
        }
    }
    // ... other repositories
}
```
</li>
</ul>

<li>Declare the dependency
<ul>
<li>
<em>Maven</em> users, add a dependency in <em>pom.xml</em>

```xml
<dependency>
    <groupId>io.github.guacsec</groupId>
    <artifactId>trustify-da-java-client</artifactId>
    <version>0.0.9-SNAPSHOT</version>
</dependency>
```
</li>

<li>
<em>Gradle</em> users, add a dependency in <em>build.gradle</em>

```groovy
implementation 'io.github.guacsec:trustify-da-java-client:${trustify-da-java-client.version}'
```
</li>
</ul>
</li>

<li>
If working with modules, configure module read

```java
module x { // module-info.java
    requires io.github.guacsec;
}
```
</li>

<li>
Code example

```java
import io.github.guacsec.trustifyda.Api.MixedReport;
import io.github.guacsec.trustifyda.impl.ExhortApi;
import io.github.guacsec.trustifyda.AnalysisReport;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;

public class TrustifyExample {
    public static void main(String... args) throws Exception {
        // instantiate the Trustify DA Java Client implementation
        var exhortApi = new ExhortApi();

        // get a byte array future holding a html Stack Analysis report
        CompletableFuture<byte[]> htmlStackReport = exhortApi.stackAnalysisHtml("/path/to/pom.xml");

        // get a AnalysisReport future holding a deserialized Stack Analysis report
        CompletableFuture<AnalysisReport> stackReport = exhortApi.stackAnalysis("/path/to/pom.xml");

        // get a AnalysisReport future holding a mixed report object aggregating:
        // - (json) deserialized Stack Analysis report
        // - (html) html Stack Analysis report
        CompletableFuture<MixedReport> mixedStackReport = exhortApi.stackAnalysisMixed("/path/to/pom.xml");

        // get a AnalysisReport future holding a deserialized Component Analysis report
        var manifestContent = Files.readAllBytes(Path.of("/path/to/pom.xml"));
        CompletableFuture<AnalysisReport> componentReport = exhortApi.componentAnalysis("/path/to/pom.xml", manifestContent);
    }
}
```
</li>
</ol>

<h3>Supported Ecosystems</h3>
<ul>
<li><a href="https://www.java.com/">Java</a> - <a href="https://maven.apache.org/">Maven</a></li>
<li><a href="https://www.javascript.com//">JavaScript</a> - <a href="https://www.npmjs.com//">Npm</a></li>
<li><a href="https://go.dev//">Golang</a> - <a href="https://go.dev/blog/using-go-modules//">Go Modules</a></li>
<li><a href="https://go.dev//">Python</a> - <a href="https://pypi.org/project/pip//">pip Installer</a></li>
<li><a href="https://gradle.org//">Gradle</a> - <a href="https://gradle.org/install//">Gradle Installation</a></li>

</ul>

<h3>Excluding Packages</h3>
<p>
Excluding a package from any analysis can be achieved by marking the package for exclusion using either the <code>trustify-da-ignore</code> syntax.

Although both `trustify-da-ignore` and `exhortignore` patterns work identically and can be used interchangeably. The `trustify-da-ignore` syntax is recommended for new projects, while `exhortignore` continues to be supported for backwards compatibility. You can gradually migrate your projects or use both patterns in the same manifest.

</p>

<ul>
<li>
<em>Java Maven</em> users can add a comment in <em>pom.xml</em>

```xml
<!-- Using trustify-da-ignore syntax -->
<dependency> <!--trustify-da-ignore-->
    <groupId>...</groupId>
    <artifactId>...</artifactId>
    <version>0.0.9-SNAPSHOT</version>
</dependency>

<!-- Using legacy exhortignore syntax -->
<dependency> <!--exhortignore-->
  <groupId>...</groupId>
  <artifactId>...</artifactId>
  <version>0.0.9-SNAPSHOT</version>
</dependency>
```
</li>

<li>
<em>Javascript NPM</em> users can add ignore arrays in <em>package.json</em>:

```json
{
  "name": "sample",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "dotenv": "^8.2.0",
    "express": "^4.17.1",
    "jsonwebtoken": "^8.5.1",
    "mongoose": "^5.9.18"
  },
  "trustify-da-ignore": [
    "jsonwebtoken"
  ]
}
```
</li>

<li>
<em>Golang</em> users can add in go.mod a comment with //trustify-da-ignore next to the package to be ignored, or to "piggyback" on existing comment ( e.g - //indirect) , for example:

```mod
module github.com/RHEcosystemAppEng/SaaSi/deployer

go 1.19

require (
        github.com/gin-gonic/gin v1.9.1
        github.com/google/uuid v1.1.2
        github.com/jessevdk/go-flags v1.5.0 //trustify-da-ignore
        github.com/kr/pretty v0.3.1
        gopkg.in/yaml.v2 v2.4.0
        k8s.io/apimachinery v0.26.1
        k8s.io/client-go v0.26.1
)

require (
        github.com/davecgh/go-spew v1.1.1 // indirect trustify-da-ignore
        github.com/emicklei/go-restful/v3 v3.9.0 // indirect
        github.com/go-logr/logr v1.2.3 // indirect trustify-da-ignore
)
```
</li>

<li>
<em>Python pip</em> users can add in requirement text a comment with #trustify-da-ignore(or # trustify-da-ignore) to the right of the same artifact to be ignored, for example:

```properties
anyio==3.6.2
asgiref==3.4.1
beautifulsoup4==4.12.2
certifi==2023.7.22
chardet==4.0.0
click==8.0.4 #trustify-da-ignore
contextlib2==21.6.0
fastapi==0.75.1
Flask==2.0.3
h11==0.13.0
idna==2.10
immutables==0.19
importlib-metadata==4.8.3
itsdangerous==2.0.1
Jinja2==3.0.3
MarkupSafe==2.0.1
pydantic==1.9.2 # trustify-da-ignore
requests==2.25.1
six==1.16.0
sniffio==1.2.0
soupsieve==2.3.2.post1
starlette==0.17.1
typing_extensions==4.1.1
urllib3==1.26.16
uvicorn==0.17.0
Werkzeug==2.0.3
zipp==3.6.0
```
</li>

<li>
<em>Gradle</em> users can add in build.gradle a comment with //trustify-da-ignore next to the package to be ignored:
```build.gradle

```groovy
plugins {
    id 'java'
}

group = 'groupName'
version = 'version'

repositories {
    mavenCentral()
}

dependencies {
    implementation "groupId:artifactId:version" // trustify-da-ignore
}

test {
    useJUnitPlatform()
}
```
</li>

</ul>

#### Ignore Strategies - experimental

You can specify the method to ignore dependencies in manifest (globally), by setting the environment variable `TRUSTIFY_DA_IGNORE_METHOD` to one of the following values:

**Possible values:**
- `insensitive` - ignoring the dependency and all of its subtree(all transitives) - default.
- `sensitive` - ignoring the dependency but let its transitives remain if they are also transitive of another dependency in the tree or if they're direct dependency of root in the dependency tree.

<h3>Customization</h3>
<p>
There are 2 approaches for customizing <em>Trustify DA Java Client</em>. Using <em>Environment Variables</em> or
<em>Java Properties</em>:

```text
System.setProperty("TRUSTIFY_DA_MVN_PATH", "/path/to/custom/mvn");
System.setProperty("TRUSTIFY_DA_NPM_PATH", "/path/to/custom/npm");
System.setProperty("TRUSTIFY_DA_PNPM_PATH", "/path/to/custom/pnpm");
System.setProperty("TRUSTIFY_DA_YARN_PATH", "/path/to/custom/yarn");
System.setProperty("TRUSTIFY_DA_GO_PATH", "/path/to/custom/go");
System.setProperty("TRUSTIFY_DA_GRADLE_PATH", "/path/to/custom/gradle");
//python - python3, pip3 take precedence if python version > 3 installed
System.setProperty("TRUSTIFY_DA_PYTHON3_PATH", "/path/to/python3");
System.setProperty("TRUSTIFY_DA_PIP3_PATH", "/path/to/pip3");
System.setProperty("TRUSTIFY_DA_PYTHON_PATH", "/path/to/python");
System.setProperty("TRUSTIFY_DA_PIP_PATH", "/path/to/pip");
// Configure proxy for all requests
System.setProperty("TRUSTIFY_DA_PROXY_URL", "http://proxy.example.com:8080");
// Configure Maven settings and repository
System.setProperty("TRUSTIFY_DA_MVN_USER_SETTINGS", "/path/to/custom/settings.xml");
System.setProperty("TRUSTIFY_DA_MVN_LOCAL_REPO", "/path/to/custom/local/repository");
```

> Environment variables takes precedence.
</p>

<h4>Customizing HTTP Version</h4>
<p>
The HTTP Client Library can be configured to use HTTP Protocol version through environment variables, so if there is a problem with one of the HTTP Versions, the other can be configured through a dedicated environment variable.  
</p>

<table>
<tr>
<th>Environment Variable</th>
<th>Accepted Values</th>
<th>Default</th>


</tr>
<tr>
<td>HTTP_VERSION_TRUSTIFY_DA_CLIENT</td>
<td>[HTTP_1_1 , HTTP_2]</td>
<td>HTTP_1_1</td>
</tr>
</table>

<h4>Proxy Configuration</h4>
<p>
You can configure a proxy for all HTTP requests made by the API. This is useful when your environment requires going through a proxy to access external services.

You can set the proxy URL in two ways:

1. Using environment variable:
```
export TRUSTIFY_DA_PROXY_URL=http://proxy.example.com:8080
```

2. Using Java Properties when calling the API programmatically:
```
System.setProperty("TRUSTIFY_DA_PROXY_URL", "http://proxy.example.com:8080");
```
</p>

<h4>Customizing Executables</h4>
<p>
This project uses each ecosystem's executable for creating dependency trees. These executables are expected to be
present on the system's PATH environment. If they are not, or perhaps you want to use custom ones. Use can use the
following keys for setting custom paths for the said executables.
</p>

<table>
<tr>
<th>Ecosystem</th>
<th>Default</th>
<th>Executable Key</th>
</tr>
<tr>
<td><a href="https://maven.apache.org/">Maven</a></td>
<td><em>mvn</em></td>
<td>TRUSTIFY_DA_MVN_PATH</td>
</tr>
<tr>
<td><a href="https://www.npmjs.com/">Node Package Manager (npm)</a></td>
<td><em>npm</em></td>
<td>TRUSTIFY_DA_NPM_PATH</td>
</tr>
<tr>
<td><a href="https://pnpm.io/">pnpm</a></td>
<td><em>pnpm</em></td>
<td>TRUSTIFY_DA_PNPM_PATH</td>
</tr>
<tr>
<td><a href="https://classic.yarnpkg.com/">Yarn (Classic)</a> / <a href="https://yarnpkg.com/">Yarn (Berry)</a></td>
<td><em>yarn</em></td>
<td>TRUSTIFY_DA_YARN_PATH</td>
</tr>
<tr>
<td><a href="https://go.dev/blog/using-go-modules/">Go Modules</a></td>
<td><em>go</em></td>
<td>TRUSTIFY_DA_GO_PATH</td>
</tr>
<tr>
<td><a href="https://gradle.org/">Gradle</a></td>
<td><em>gradle</em></td>
<td>TRUSTIFY_DA_GRADLE_PATH</td>
</tr>
<tr>
<td><a href="https://www.python.org/">Python programming language</a></td>
<td><em>python3</em></td>
<td>TRUSTIFY_DA_PYTHON3_PATH</td>
</tr>
<tr>
<td><a href="https://pypi.org/project/pip/">Python pip Package Installer</a></td>
<td><em>pip3</em></td>
<td>TRUSTIFY_DA_PIP3_PATH</td>
</tr>
<tr>
<td><a href="https://www.python.org/">Python programming language</a></td>
<td><em>python</em></td>
<td>TRUSTIFY_DA_PYTHON_PATH</td>
</tr>
<tr>
<td><a href="https://pypi.org/project/pip/">Python pip Package Installer</a></td>
<td><em>pip</em></td>
<td>TRUSTIFY_DA_PIP_PATH</td>
</tr>

</table>

#### Maven Configuration

You can customize Maven behavior by setting additional environment variables or Java properties:

<table>
<tr>
<th>Configuration</th>
<th>Environment Variable</th>
<th>Description</th>
<th>Default</th>
</tr>
<tr>
<td>Maven User Settings</td>
<td>TRUSTIFY_DA_MVN_USER_SETTINGS</td>
<td>Path to custom Maven settings.xml file</td>
<td><em>Uses Maven's default settings</em></td>
</tr>
<tr>
<td>Maven Local Repository</td>
<td>TRUSTIFY_DA_MVN_LOCAL_REPO</td>
<td>Path to custom Maven local repository directory</td>
<td><em>Uses Maven's default local repository</em></td>
</tr>
</table>

**Examples:**

Using environment variables:
```bash
export TRUSTIFY_DA_MVN_USER_SETTINGS=/home/user/.m2/custom-settings.xml
export TRUSTIFY_DA_MVN_LOCAL_REPO=/home/user/custom-maven-repo
```

Using Java properties:
```text
System.setProperty("TRUSTIFY_DA_MVN_USER_SETTINGS", "/home/user/.m2/custom-settings.xml");
System.setProperty("TRUSTIFY_DA_MVN_LOCAL_REPO", "/home/user/custom-maven-repo");
```

> Environment variables take precedence over Java properties.

#### Match Manifest Versions Feature

##### Background

In Python pip and in golang go modules package managers ( especially in Python pip) , There is a big chance that for a certain manifest and a given package inside it, the client machine environment has different version installed/resolved
for that package, which can lead to perform the analysis on the installed packages' versions , instead on the declared versions ( in manifests - that is requirements.txt/go.mod ), and this
can cause a confusion for the user in the client consuming the API and leads to inconsistent output ( in THE manifest there is version X For a given Package `A` , and in the analysis report there is another version for the same package `A` - Y).

##### Usage

To eliminate confusion and improve clarity as discussed above, the following setting was introduced - `MATCH_MANIFEST_VERSIONS`, in the form of environment variable/key in opts ( as usual , environment variable takes precedence )
for two ecosystems:
 - Golang - Go Modules
 - Python - pip

Two possible values for this setting:

1. MATCH_MANIFEST_VERSIONS="false" - means that if installed/resolved versions of packages are different than the ones declared in the manifest, the process will ignore this difference and will continue to analysis with installed/resolved versions ( this is the original logic flow )
<br>


2. MATCH_MANIFEST_VERSIONS="true" - means that before starting the analysis,
   the api will compare all the versions of packages in manifest against installed/resolved versions on client' environment, in case there is a difference, it will throw an error to the client/user with message containing the first encountered versions mismatch, including package name, and the versions difference, and will suggest to set setting `MATCH_MANIFEST_VERSIONS`="false" to ignore all differences

#### Golang Support

By default, Golang dependency resolution follows the [Minimal Version Selection (MVS) Algorithm](https://go.dev/ref/mod#minimal-version-selection).  
This means that when analyzing a project, only the module versions that would actually be included in the final executable are considered.

For example, if your `go.mod` file declares two modules, `a` and `b`, and both depend on the same package `c` (same major version `v1`) but with different minor versions:

- `namespace/c/v1@v1.1`
- `namespace/c/v1@v1.2`

Only one of these versions — the minimal version selected by MVS — will be included in the generated SBOM and analysis results.  
This mirrors the behavior of a real Go build, where only one minor version of a given major version can be present in the executable (since Go treats packages with the same name and major version as identical).

The MVS-based resolution is **enabled by default**.  
If you want to disable this behavior and instead include **all transitive module versions** (as listed in `go.mod` dependencies), set the system property or environment variable:

```bash
TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED=false
```

####  Python Support

By default, Python support assumes that the package is installed using the pip/pip3 binary on the system PATH, or of the customized
Binaries passed to environment variables. If the package is not installed , then an error will be thrown.

There is an experimental feature of installing the requirement.txt on a virtual env(only python3 or later is supported for this feature) - in this case,
it's important to pass in a path to python3 binary as `TRUSTIFY_DA_PYTHON3_PATH` or instead make sure that python3 is on the system path.
in such case, You can use that feature by setting environment variable `TRUSTIFY_DA_PYTHON_VIRTUAL_ENV` to true 

##### "Best Efforts Installation"
Since Python pip packages are very sensitive/picky regarding python version changes( every small range of versions is only tailored for a certain python version), I'm introducing this feature, that
tries to install all packages in requirements.txt onto created virtual environment while **disregarding** versions declared for packages in requirements.txt
This increasing the chances and the probability a lot that the automatic installation will succeed.

##### Usage
A New setting is introduced - `TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS` (as both env variable/key in `options` object)
1. `TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS`="false" - install requirements.txt while respecting declared versions for all packages.
2. `TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS`="true" - install all packages from requirements.txt, not respecting the declared version, but trying to install a version tailored for the used python version, when using this setting,you must set setting `MATCH_MANIFEST_VERSIONS`="false"

##### Using `pipdeptree`
By Default, The API algorithm will use native commands of PIP installer as data source to build the dependency tree.
It's also possible, to use lightweight Python PIP utility [pipdeptree](https://pypi.org/project/pipdeptree/) as data source instead, in order to activate this,
Need to set environment variable/system property - `TRUSTIFY_DA_PIP_USE_DEP_TREE` to true.

### CLI Support

The Trustify DA Java Client includes a command-line interface for standalone usage.

#### Building the CLI

To build the CLI JAR with all dependencies included:

```shell
mvn clean package
```

This creates two JAR files in the `target/` directory:
- `trustify-da-java-client.jar` - Library JAR (for programmatic use)
- `trustify-da-java-client-cli.jar` - CLI JAR (includes all dependencies)

#### Usage

```shell
java -jar target/trustify-da-java-client-cli.jar <COMMAND> <FILE_PATH> [OPTIONS]
```

#### Commands

**Stack Analysis**
```shell
java -jar trustify-da-java-client-cli.jar stack <file_path> [--summary|--html]
```
Perform stack analysis on the specified manifest file.

Options:
- `--summary` - Output summary in JSON format
- `--html` - Output full report in HTML format
- (default) - Output full report in JSON format

**Component Analysis**
```shell
java -jar trustify-da-java-client-cli.jar component <file_path> [--summary]
```
Perform component analysis on the specified manifest file.

Options:
- `--summary` - Output summary in JSON format
- (default) - Output full report in JSON format

**Image Analysis**
```shell
java -jar trustify-da-java-client-cli.jar image <image_ref> [<image_ref>...] [--summary|--html]
```
Perform security analysis on the specified container image(s).

Arguments:
- `<image_ref>` - Container image reference (e.g., `nginx:latest`, `registry.io/image:tag`)
- Multiple images can be analyzed at once
- Optionally specify platform with `^^` notation (e.g., `image:tag^^linux/amd64`)

Options:
- `--summary` - Output summary in JSON format
- `--html` - Output full report in HTML format
- (default) - Output full report in JSON format

#### Backend Configuration

The client requires the backend URL to be configured through the environment variable:

- **Environment variable**: `TRUSTIFY_DA_BACKEND_URL=https://backend.url` (required)

The application will fail to start if this environment variable is not set.

#### Examples

```shell
export TRUSTIFY_DA_BACKEND_URL=https://your-backend.url

# Stack analysis with JSON output (default)
java -jar trustify-da-java-client-cli.jar stack /path/to/pom.xml

# Stack analysis with summary
java -jar trustify-da-java-client-cli.jar stack /path/to/package.json --summary

# Stack analysis with HTML output
java -jar trustify-da-java-client-cli.jar stack /path/to/build.gradle --html

# Component analysis with JSON output (default)
java -jar trustify-da-java-client-cli.jar component /path/to/requirements.txt

# Component analysis with summary
java -jar trustify-da-java-client-cli.jar component /path/to/go.mod --summary

# Container image analysis with JSON output (default)
java -jar trustify-da-java-client-cli.jar image nginx:latest

# Multiple container image analysis
java -jar trustify-da-java-client-cli.jar image nginx:latest docker.io/library/node:18

# Container image analysis with platform specification
java -jar trustify-da-java-client-cli.jar image nginx:latest^^linux/amd64 --summary

# Container image analysis with HTML output
java -jar trustify-da-java-client-cli.jar image quay.io/redhat/ubi8:latest --html

# Show help
java -jar trustify-da-java-client-cli.jar --help
```

### Image Support 

Generate vulnerability analysis report for container images.

#### Code Example
```java
package io.github.guacsec.trustifyda;

import io.github.guacsec.trustifyda.api.AnalysisReport;
import io.github.guacsec.trustifyda.image.ImageRef;
import io.github.guacsec.trustifyda.impl.ExhortApi;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class TrustifyImageExample {

    public static void main(String[] args) throws Exception {
        // instantiate the Trustify DA Java Client implementation
        var exhortApi = new ExhortApi();

        // create a reference to image test1 by specifying image name and its platform when applicable
        var imageRef1 = new ImageRef("quay.io/test/test1:latest", "linux/amd64");

        // create a reference to image test2 by specifying image name
        var imageRef2 = new ImageRef("quay.io/test/test2:latest", null);

        // get a byte array future holding a html Image Analysis reports
        CompletableFuture<byte[]> htmlImageReport = exhortApi.imageAnalysisHtml(Set.of(imageRef1, imageRef2));

        // get a map of AnalysisReport future holding a deserialized Image Analysis reports
        CompletableFuture<Map<ImageRef, AnalysisReport>> imageReport = exhortApi.imageAnalysis(Set.of(imageRef1, imageRef2));
    }
}
```

#### Prerequisites
Installation of the tools/cli for analyzing image vulnerability.

| Tool   | CLI Installation                                                        | Required |
|--------|-------------------------------------------------------------------------|----------|
| Syft   | [syft](https://github.com/anchore/syft?tab=readme-ov-file#installation) | True     |
| Skopeo | [skopeo](https://github.com/containers/skopeo/blob/main/install.md)     | True     |
| Docker | [docker](https://docs.docker.com/get-docker/)                           | False    |
| Podman | [podman](https://podman.io/docs/installation)                           | False    |

#### Customization
Customize image analysis optionally by using *Environment Variables* or *Java Properties*.

| Env / Property                | Description                                                                                                                                                     | Default Value                                                                                                                                 |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| TRUSTIFY_DA_SYFT_PATH              | Custom path to the `syft` executable                                                                                                                            | syft                                                                                                                                          |
| TRUSTIFY_DA_SYFT_CONFIG_PATH       | Custom path to the `syft` [configuration file](https://github.com/anchore/syft?tab=readme-ov-file#configuration)                                                | .syft.yaml, .syft/config.yaml, $HOME/.syft.yaml                                                                                               |
| TRUSTIFY_DA_SYFT_IMAGE_SOURCE      | [Source](https://github.com/anchore/syft?tab=readme-ov-file#supported-sources) from which `syft` looks for the images (e.g. docker, podman, registry)           | (By default, Syft attempts to resolve it using: the Docker, Podman, and Containerd daemons followed by direct registry access, in that order) |
| TRUSTIFY_DA_SKOPEO_PATH            | Custom path to the `skopeo` executable                                                                                                                          | skopeo                                                                                                                                        |
| TRUSTIFY_DA_SKOPEO_CONFIG_PATH     | Custom path to the [authentication file](https://github.com/containers/skopeo/blob/main/docs/skopeo-inspect.1.md#options) used by `skopeo inspect`              | $HOME/.docker/config.json                                                                                                                     |
| TRUSTIFY_DA_IMAGE_SERVICE_ENDPOINT | [Host endpoint](https://github.com/containers/skopeo/blob/main/docs/skopeo-inspect.1.md#options) of the container runtime daemon / service                      |                                                                                                                                               |
| TRUSTIFY_DA_DOCKER_PATH            | Custom path to the `docker` executable                                                                                                                          | docker                                                                                                                                        |
| TRUSTIFY_DA_PODMAN_PATH            | Custom path to the `podman` executable                                                                                                                          | podman                                                                                                                                        |
| TRUSTIFY_DA_IMAGE_PLATFORM         | Default platform used for multi-arch images                                                                                                                     |                                                                                                                                               |
| TRUSTIFY_DA_IMAGE_OS               | Default OS used for multi-arch images when `TRUSTIFY_DA_IMAGE_PLATFORM` is not set                                                                                   |                                                                                                                                               |
| TRUSTIFY_DA_IMAGE_ARCH             | Default Architecture used for multi-arch images when `TRUSTIFY_DA_IMAGE_PLATFORM` is not set                                                                         |                                                                                                                                               |
| TRUSTIFY_DA_IMAGE_VARIANT          | Default Variant used for multi-arch images when `TRUSTIFY_DA_IMAGE_PLATFORM` is not set                                                                              |                                                                                                                                               |

### Releases

To create a new release:

1. **Trigger Release Workflow**: Go to Actions → "Release Version" → "Run workflow"
2. **Choose Version**:
   - Leave version empty to automatically release current snapshot (e.g., `0.0.9-SNAPSHOT` → `0.0.9`)
   - Or specify custom version (e.g., `1.0.0`)
3. **Automatic Process**: The workflow will:
   - Publish to Maven Central
   - Create GitHub release with auto-generated notes
   - Bump to next development version via pull request

Released artifacts are available on [Maven Central](https://repo1.maven.org/maven2/io/github/guacsec/trustify-da-java-client/).

### Known Issues

- For pip requirements.txt - It's been observed that for python versions 3.11.x, there might be slowness for invoking the analysis.
  If you encounter a performance issue with python version >= 3.11.x, kindly try to set environment variable/system property `TRUSTIFY_DA_PIP_USE_DEP_TREE`=true, before calling the analysis - this should fix the performance issue.



- For maven pom.xml, it has been noticed that using java 17 might cause stack analysis to hang forever.
  This is caused by maven [`dependency` Plugin](https://maven.apache.org/plugins/maven-dependency-plugin/) bug when running with JDK/JRE' JVM version 17.

  To overcome this, you can use any other java version (14,20,21, etc..). ( best way is to install JDK/JRE version different from 17 , and set the location of the installation in environment variable `JAVA_HOME` so maven will use it.)


<!-- Badge links -->
[0]: https://img.shields.io/github/v/release/guacsec/trustify-da-java-client?color=green&label=latest
[1]: https://img.shields.io/github/v/release/guacsec/trustify-da-java-client?color=yellow&include_prereleases&label=snapshot
