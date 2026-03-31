---
description: "Code quality standards — coverage thresholds, testing patterns, complexity limits"
applyTo: "**/*.ts,**/*.js,**/*.py,**/*.cs,**/*.java,**/*.go"
---

# Code Quality Standards

These rules apply automatically when editing source code files. Follow these standards to maintain code quality, test coverage, and maintainability.

## Coverage Thresholds

All projects MUST maintain the following minimum coverage levels.

| Metric | Threshold | Enforcement |
|---|---|---|
| Line coverage | ≥ 80% | CI gate — block merge if below |
| Branch coverage | ≥ 80% | CI gate — block merge if below |
| Function coverage | ≥ 80% | CI gate — block merge if below |
| New code coverage | ≥ 90% | PR check — warn if below |

### Coverage Rules

- Every new public function MUST have at least one test.
- Every changed function MUST maintain or improve its coverage percentage.
- Coverage regressions (overall drop) MUST be resolved before merge.
- Exclude generated code, configuration files, and type declarations from coverage metrics.

### Coverage Exclusion Patterns

Use framework-specific exclusion annotations for code that cannot be meaningfully tested:

| Language | Exclusion Mechanism |
|---|---|
| TypeScript/JavaScript | `/* istanbul ignore next */`, `/* c8 ignore next */` |
| Python | `# pragma: no cover` |
| C# | `[ExcludeFromCodeCoverage]` attribute |
| Java | Lombok-generated code, framework annotations |
| Go | Build tag `//go:build ignore` for test utilities |

Exclusions MUST include a comment explaining why the code is excluded.

## Testing Patterns

### Unit Tests

- Write unit tests for all public functions and methods.
- Each test verifies a single behavior (one logical assertion per test).
- Use descriptive test names that document the expected behavior.
- Structure tests with Arrange-Act-Assert (AAA) pattern.
- Mock only external dependencies (APIs, databases, file system), never the unit under test.

### Integration Tests

- Write integration tests for all API endpoints and service boundaries.
- Test request/response contracts including status codes, headers, and body schema.
- Test error responses (400, 401, 403, 404, 500) with appropriate payloads.
- Use test databases or in-memory stores rather than mocking data layers.

### Error Path Coverage

- Test all explicit error handling paths (try/catch, guard clauses, validation).
- Test boundary conditions (empty input, null values, maximum length, overflow).
- Test concurrent access patterns where applicable.

### Test File Naming Conventions

| Language | Source File | Test File Location |
|---|---|---|
| TypeScript/JavaScript | `src/utils/parser.ts` | `src/utils/parser.test.ts` or `tests/utils/parser.test.ts` |
| Python | `src/utils/parser.py` | `tests/utils/test_parser.py` |
| C# | `Services/ParserService.cs` | `Tests/Services/ParserServiceTests.cs` |
| Java | `src/main/.../Parser.java` | `src/test/.../ParserTest.java` |
| Go | `pkg/parser/parser.go` | `pkg/parser/parser_test.go` (co-located) |

## Complexity Limits

### Cyclomatic Complexity

- Maximum cyclomatic complexity per function: **10**.
- Functions exceeding this limit MUST be refactored into smaller, composable functions.
- Use early returns to reduce nesting depth.

### Nesting Depth

- Maximum nesting depth: **4 levels**.
- Extract deeply nested logic into named helper functions.

### Function Length

- Recommended maximum: **50 lines** per function.
- Functions exceeding 50 lines SHOULD be reviewed for extraction opportunities.

### Cognitive Complexity

- Prefer simple, linear control flow.
- Avoid nested ternary expressions.
- Extract complex boolean conditions into named variables or functions.

## Lint and Style

### General Rules

- All projects MUST have a linter configured and enforced in CI.
- Lint violations MUST NOT be committed; fix them before push.
- Use project-level linter configuration; do not disable rules inline without justification.

### Language-Specific Linters

| Language | Linter | Configuration |
|---|---|---|
| TypeScript/JavaScript | ESLint | `eslint.config.js` or `.eslintrc.*` |
| Python | Ruff or Flake8 + Black | `pyproject.toml` or `setup.cfg` |
| C# | .NET Analyzers + StyleCop | `.editorconfig`, `Directory.Build.props` |
| Java | Checkstyle or SpotBugs | `checkstyle.xml`, `spotbugs.xml` |
| Go | golangci-lint | `.golangci.yml` |

## Code Duplication

- Avoid duplicating logic across files; extract shared behavior into utility functions.
- Flag blocks of 10+ similar consecutive lines as duplication candidates.
- Use shared abstractions for repeated patterns (factory functions, base classes, traits).

## CI/CD Quality Gate

The following checks MUST pass in CI before merge:

```text
1. Lint check passes (zero violations)
2. Type check passes (TypeScript: tsc --noEmit, Python: mypy/pyright, C#: build)
3. All tests pass
4. Coverage meets threshold (≥ 80% line, branch, function)
5. No coverage regressions on changed files
6. SARIF upload for coverage findings
```

### Quality Gate SARIF Integration

Coverage findings are uploaded to GitHub Security Overview using the `code-quality/coverage/` automation category. This enables tracking quality trends alongside security and accessibility findings in a unified dashboard.
