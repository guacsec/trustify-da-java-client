
<b>Pattern 1: Require explicit runtime configuration for backend/service endpoints and fail fast when required environment variables or CLI arguments are missing, rather than shipping defaults or vendor-specific endpoints. Ensure docs and examples stay provider-agnostic and do not include internal/third-party service URLs.
</b>

Example code before:
```
private static final String DEFAULT_ENDPOINT = "https://vendor.example.com";

String endpoint = Environment.get("BACKEND_URL", DEFAULT_ENDPOINT);
// continues with default even when not configured
```

Example code after:
```
String endpoint = Environment.get("BACKEND_URL");
if (endpoint == null || endpoint.trim().isEmpty()) {
  throw new IllegalStateException(
      "Backend URL not configured. Please set BACKEND_URL.");
}
endpoint = endpoint.trim();
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-java-client/pull/211#discussion_r2536810895
- https://github.com/guacsec/trustify-da-java-client/pull/211#discussion_r2537678862
</details>


___

<b>Pattern 2: When introducing a new configuration key/behavior that supersedes a legacy one, enforce deterministic precedence (new overrides old) and migrate examples/docs to primarily show the new key; only mention the legacy key as backwards compatibility. In code, centralize these keys as constants and implement the precedence logic once.
</b>

Example code before:
```
// scattered literals and unclear precedence
var node = json.get("legacyIgnore");
if (node == null || node.isEmpty()) {
  node = json.get("newIgnore");
}
```

Example code after:
```
// constants + explicit precedence: new wins
var node = json.get(IGNORE_NEW);
if (node == null || node.isEmpty()) {
  node = json.get(IGNORE_LEGACY);
}
if (node == null || node.isEmpty()) return Set.of();
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-java-client/pull/205#discussion_r2526224893
- https://github.com/guacsec/trustify-da-java-client/pull/205#discussion_r2526228973
- https://github.com/guacsec/trustify-da-java-client/pull/205#discussion_r2526232347
- https://github.com/guacsec/trustify-da-java-client/pull/205#discussion_r2526242594
- https://github.com/guacsec/trustify-da-java-client/pull/205#discussion_r2526258368
</details>


___

<b>Pattern 3: Prefer failing with exceptions (and include stderr/context) over merely logging when an external tool/process invocation or required precondition fails, so callers get actionable failures. Use logging for diagnostics, not as a substitute for error handling.
</b>

Example code before:
```
String out = Operations.run(cmd);
if (out == null) {
  LOG.warning("Tool failed, continuing");
  return "";
}
```

Example code after:
```
ProcessResult r = Operations.runWithResult(cmd);
if (r.exitCode() != 0) {
  throw new IOException("Tool failed: " + r.stderr());
}
return r.stdout();
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-java-client/pull/167#discussion_r2228021393
</details>


___

<b>Pattern 4: Keep documentation and code comments minimal, accurate, and non-redundant: avoid repeating the same environment-variable setup in every example, remove outdated/irrelevant comments, and ensure parameter names match their Javadoc. Prefer a single “export once” step and then concise usage examples.
</b>

Example code before:
```
# Example 1
export BACKEND_URL=http://localhost:8080
tool cmd1

# Example 2
export BACKEND_URL=http://localhost:8080
tool cmd2
```

Example code after:
```
# Configure once
export BACKEND_URL=http://localhost:8080

# Examples
tool cmd1
tool cmd2
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-java-client/pull/211#discussion_r2537683064
- https://github.com/guacsec/trustify-da-java-client/pull/211#discussion_r2537686339
- https://github.com/guacsec/trustify-da-java-client/pull/127#discussion_r2047246406
- https://github.com/guacsec/trustify-da-java-client/pull/114#discussion_r2031484262
</details>


___
