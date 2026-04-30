# GoModulesProvider Architecture

## Dependency Resolution Flow
1. `getDependenciesSbom(Path, boolean)` orchestrates: runs `go mod graph`, `go mod edit -json`, determines main module version
2. `buildGoModulesDependencies(Path)` - runs `go mod graph` to get full dependency graph
3. `getDirectDependencyPaths(Path)` - runs `go mod edit -json` to identify direct vs indirect deps
4. For stack analysis: `buildSbomFromGraph` builds full dependency tree
5. For component analysis: `buildSbomFromList` lists only direct dependencies

## Direct vs Indirect Filtering (TC-4300)
- Since Go 1.17, `go mod tidy` adds all transitively-imported modules to go.mod with `// indirect` marker
- `go mod graph` emits root-level edges for ALL modules in go.mod (both direct and indirect)
- `go mod edit -json` returns structured JSON with `Require` array where each entry has optional `Indirect: true`
- Both `buildSbomFromGraph` and `buildSbomFromList` filter root-level deps to only include direct ones

## Key Gotcha: MVS Version Suffix
After MVS processing (`getFinalPackagesVersionsForModule`), the root key in the edges map changes from `module/path` to `module/path@v0.0.0`. The root comparison must use `getModulePath()` to strip the version suffix for both sides, otherwise the filtering silently does nothing when MVS is enabled.

## Helper Methods
- `getModulePath(String)` - strips `@version` suffix from `go mod graph` entries (e.g., `github.com/foo/bar@v1.2.3` -> `github.com/foo/bar`)
- `extractPackageName(String)` - strips `//` comment from go.mod require lines (different purpose, don't confuse)
- `getParentVertex(String)` / `getChildVertex(String)` - split `go mod graph` edge lines on space
- `isGoToolchainEntry(String)` - filters out `go@` and `toolchain@` entries

## Test Fixtures
- `src/test/resources/tst_manifests/golang/` - main test fixtures with 6 test folders
- `src/test/resources/msc/golang/mvs_logic/` - MVS-specific test fixtures
- Tests use `dropIgnoredKeepFormat()` to strip timestamps and goarch/goos before comparison
- Tests use `prettyJson()` (Jackson) to normalize JSON formatting
