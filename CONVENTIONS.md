# Coding Conventions

<!-- This file documents project-specific coding standards for exhort-java-api. -->

## Language and Framework

- **Primary Language**: Java 17
- **Build Tool**: Maven 3.8+
- **Module System**: Java 9+ modules (`module-info.java`)
- **Key Libraries**: Jackson 2.20.0 (JSON), CycloneDX 11.0.1 (SBOM), Jakarta Mail/Annotation APIs
- **Async Model**: `CompletableFuture` throughout the API

## Code Style

- **Formatter**: Spotless Maven Plugin with Google Java Format (GOOGLE style, `reflowLongStrings` enabled)
- **Indentation**: 2 spaces for Java, XML, YAML; 2 spaces for JSON
- **Line length**: 100 characters (120 for XML/FXML)
- **Line endings**: LF
- **Charset**: UTF-8
- **License header**: Apache 2.0, automatically injected by Spotless
- **EditorConfig**: `.editorconfig` enforces formatting rules
- **Code coverage**: 81% unit test threshold (JaCoCo), 50 mutation threshold (PIT)

## Naming Conventions

- **Packages**: `io.github.guacsec.trustifyda.*`
- **Classes**: PascalCase
  - Providers: `*Provider` (e.g., `JavaMavenProvider`, `PythonPipProvider`)
  - Factories: `*Factory` (e.g., `JavaScriptProviderFactory`, `SbomFactory`)
  - Abstract bases: `Base*Provider` (e.g., `BaseJavaProvider`)
  - Utility classes: `final` with private constructor
- **Interfaces**: Simple names without `I` prefix (`Api`, `Provider`, `Sbom`)
  - Inner static classes for related types: `Api.MediaType`, `Provider.Content`
- **Methods**: camelCase (`provideStack()`, `provideComponent()`, `getCustomPathOrElse()`)
- **Constants**: UPPER_SNAKE_CASE (`TRUSTIFY_DA_BACKEND_URL`, `CYCLONEDX_MEDIA_TYPE`)
- **Enums**: PascalCase class, UPPER_CASE values (`MAVEN`, `NPM`, `GRADLE`)
- **Test classes**: Snake_case pattern (`Operations_Test`, `Java_Maven_Provider_Test`)

## File Organization

```
src/main/java/io/github/guacsec/trustifyda/
├── Api.java                    # Main interface
├── Provider.java               # Abstract provider contract
├── cli/                        # CLI implementation
├── exception/                  # Custom exceptions
├── image/                      # Image analysis
├── impl/                       # ExhortApi implementation, RequestManager
├── logging/                    # LoggersFactory
├── providers/                  # 18+ ecosystem provider implementations
├── sbom/                       # SBOM handling (Sbom, SbomFactory, CycloneDXSbom)
├── tools/                      # Utilities (Ecosystem, Operations)
├── utils/                      # Environment, IgnorePatternDetector
└── vcs/                        # Version control utilities
```

- Test resources: `src/test/resources/tst_manifests/`
- Integration tests: `src/it/` (Maven Invoker Plugin)

## Error Handling

- Runtime exceptions preferred over checked (e.g., `PackageNotInstalledException extends RuntimeException`)
- `CompletableFuture` for async operations with completion exception handling
- `IOException` allowed for file operations (checked exception)
- Environment validation at initialization time
- Logging via `LoggersFactory.getLogger()` (Java Logging API)

## Testing Conventions

- **Frameworks**: JUnit Jupiter 5, Mockito 5.17.0, AssertJ 3.27.3
- **Extensions**: JUnit Pioneer (`@SetSystemProperty`, `@ClearSystemProperty`)
- **Assertions**: AssertJ fluent API (`assertThat()`, `assertThatRuntimeException()`)
- **Mocking**: Mockito (`@Mock`, `@InjectMocks`, `mockStatic()`, BDDMockito)
- **Test structure**: `@Nested` classes, `@ParameterizedTest @MethodSource`
- **Test naming**: Snake_case classes, descriptive methods (`when_running_process_for_existing_command_should_not_throw_exception`)
- **Test runner**: junit-platform-maven-plugin

## Commit Messages

- Follow Conventional Commits: `type(scope): description`
- DCO sign-off required
- Pull request titles must follow Conventional Commits format

## Test Fixtures

- **Dependabot suppression**: Test fixture directories contain intentionally pinned (sometimes vulnerable) dependencies. When adding a new test fixture directory with a manifest file, review `.github/dependabot.yml` to ensure the new path is covered. Non-maven ecosystems are suppressed via root-level `ignore: [{dependency-name: "*"}]` entries. Maven fixtures use per-directory entries with `/**` globs since maven is the production ecosystem; add the parent directory if a new maven fixture tree is introduced.

## Test Fixtures

- **Dependabot suppression**: Test fixture directories contain intentionally pinned (sometimes vulnerable) dependencies. When adding a new test fixture directory with a manifest file, review `.github/dependabot.yml` to ensure the new path is covered. Non-maven ecosystems are suppressed via root-level `ignore: [{dependency-name: "*"}]` entries. Maven fixtures use explicit per-directory entries since maven is the production ecosystem; add the directory path if a new maven fixture is introduced.

## Dependencies

- All versions in `<properties>` section: `{artifact-name}.version` pattern
- Compile scope: Jackson, Jakarta, CycloneDX, TOML parsers
- Test scope: JUnit, Mockito, AssertJ, JUnit Pioneer
- Maven Shade Plugin for CLI JAR with all dependencies
- Distribution to Maven Central (flatten plugin, OSSRH mode)
- GitHub Maven repository for `trustify-da-api-model`
- Enforcer plugin: dependency convergence, no circular dependencies
