# Dev Tooling Setup: Ruff + Pre-commit + Mypy

## Overview

Implement the same development tooling stack used in IPI-Canary: ruff (linter/formatter), pre-commit (git hooks), and mypy (type checker). This is done across two feature branches with incremental commits.

## Git Workflow (Mandatory)

**Never work directly on main.** All work happens on feature branches.

```bash
git status              # Must be clean
git branch              # Must be on main before branching
git checkout -b feature/branch-name
# ... do work ...
git push -u origin feature/branch-name
# User creates PR on GitHub, merges, then tells you
# Then: git checkout main && git pull
```

## Phase 1: Ruff + Pre-commit (branch: `feature/ruff-precommit`)

### Step 1: Assess the project

Before writing any config, understand the codebase:
- What Python version does the project target?
- What's the package layout? (`src/` layout vs flat?)
- Are there test directories, scripts, or other non-core code that need relaxed rules?
- Does `pyproject.toml` already exist? What build system?

### Step 2: Add ruff config to pyproject.toml

Add ruff and pre-commit to dev dependencies, then add tool config.

**Core ruff config — adapt paths/ignores to this project:**

```toml
[tool.ruff]
line-length = 100
target-version = "py311"  # Match project's minimum Python version

[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "F",    # pyflakes
    "I",    # isort (import sorting)
    "N",    # pep8-naming
    "W",    # pycodestyle warnings
    "B",    # flake8-bugbear (common bugs)
    "C90",  # mccabe complexity
    "UP",   # pyupgrade (modernize syntax)
    "S",    # flake8-bandit (security)
]
ignore = [
    "S101",   # assert usage (fine in tests)
    # Add project-specific ignores as needed
]

[tool.ruff.lint.mccabe]
max-complexity = 15

[tool.ruff.lint.per-file-ignores]
# Adapt these to the actual project structure:
# "tests/*" = ["S"]           # Tests: skip security checks
# "scripts/*" = ["S", "E501"] # Utility scripts: relaxed
```

**Important:** Per-file ignores should be tailored to this project's directory structure. Don't blindly copy IPI-Canary's ignores — assess what directories exist and what relaxations make sense.

### Step 3: Run ruff and fix

```bash
# First, see what you're dealing with
ruff check . 2>&1 | tail -5    # Count errors
ruff check . --statistics       # See error categories

# Auto-fix what's safe
ruff check --fix .

# Format
ruff format .

# Verify clean
ruff check .
ruff format --check .
```

**Commit the config and auto-fixes separately:**
1. First commit: Config changes to pyproject.toml only
2. Second commit: Auto-fixed code changes

### Step 4: Create .pre-commit-config.yaml

**Before creating this file, verify current versions:**
- Check https://github.com/pre-commit/pre-commit-hooks/releases for latest tag
- Check https://github.com/astral-sh/ruff-pre-commit/releases for latest tag
- Use the versions that are current, not the ones listed below

```yaml
# Pre-commit hooks for [PROJECT NAME]
# Install: pre-commit install
# Run all: pre-commit run --all-files
# Update: pre-commit autoupdate

repos:
  # General file hygiene
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0  # VERIFY THIS IS CURRENT
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-toml
      - id: check-added-large-files
        args: ['--maxkb=1000']
      - id: check-merge-conflict
      - id: no-commit-to-branch
        args: ['--branch', 'main']

  # Ruff linter + formatter
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.0  # VERIFY THIS IS CURRENT
    hooks:
      - id: ruff
        args: ['--fix']
      - id: ruff-format
```

### Step 5: Install and verify

```bash
pre-commit install
pre-commit run --all-files
```

All hooks must pass. Fix any issues the file hygiene hooks catch (trailing whitespace, missing EOF newlines).

### Step 6: Commit, push, tell user to create PR

Commit the .pre-commit-config.yaml and any hygiene fixes. Push branch.

---

## Phase 2: Mypy (branch: `feature/mypy-typecheck`)

Only start this after Phase 1 PR is merged and you've pulled main.

### Step 1: Add mypy config to pyproject.toml

```toml
[tool.mypy]
python_version = "3.11"  # Match project
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = false    # Don't require annotations everywhere yet
check_untyped_defs = true        # But DO check the bodies of untyped functions
ignore_missing_imports = true    # Third-party libs without stubs

# Add overrides for directories that should be excluded:
# [[tool.mypy.overrides]]
# module = "tests.*"
# ignore_errors = true
```

Add `mypy>=1.10.0` to dev dependencies.

### Step 2: Run baseline mypy

```bash
mypy src/package_name/    # or wherever the source is
```

Categorize every error before fixing anything. Common patterns:

| Pattern | Fix |
|---------|-----|
| Library has no stubs / poor type exports | `TYPE_CHECKING` import with proper type alias |
| Library function returns union type | `# type: ignore[assignment]` with comment explaining why |
| Missing `Optional` / implicit None default | Use `X \| None` syntax (modern, ruff-compatible) |
| Missing type annotation on variable | Add explicit annotation: `var: dict[str, list[Thing]] = {}` |
| Argument type mismatch from DB/external data | Wrap in constructor: `Format(row["format"])` |
| `list` where `tuple` expected | Change `[a, b, c]` to `(a, b, c)` |

### Step 3: Fix errors

**Strategy for third-party library type issues:**
- If the library has a `types-*` package (e.g., `types-Pillow`, `types-requests`), install it and use it
- If the library's type stubs are wrong about a return type that's correct in practice, use `# type: ignore[assignment]`
- If a library exports a factory function instead of a class (like `python-docx`'s `Document()`), use `TYPE_CHECKING` pattern:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from library.actual_module import ActualClass as TypeAlias
```

**Always verify ruff is still happy after mypy fixes** — ruff's `UP` rules may conflict with `Optional[X]` (it prefers `X | None`).

### Step 4: Add mypy to pre-commit

Add this block to `.pre-commit-config.yaml`:

```yaml
  # Mypy type checker
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.19.1  # VERIFY THIS IS CURRENT
    hooks:
      - id: mypy
        args: ['--config-file=pyproject.toml', 'src/package_name/']  # ADAPT PATH
        additional_dependencies:
          - types-Pillow      # Only include stubs this project actually needs
          - types-requests    # Add/remove based on what the project imports
        pass_filenames: false
        files: ^src/package_name/   # ADAPT PATH
```

**Critical:** The `additional_dependencies` list must include any `types-*` packages the project needs. The pre-commit mypy hook runs in its own isolated environment — it won't see packages from your venv. If you skip a stub package here, pre-commit may find different errors than local mypy.

### Step 5: Verify everything together

```bash
# All three must pass:
mypy src/package_name/
ruff check .
ruff format --check .
pre-commit run --all-files

# Smoke test - make sure the project still works:
# Run whatever the project's CLI or entry point is
```

### Step 6: Commit, push, tell user to create PR

Two commits:
1. Config: pyproject.toml mypy settings + pre-commit hook update
2. Fixes: All type error resolutions across source files

---

## Key Principles

- **Verify package versions before using them.** Don't assume the versions in this document are current. Check PyPI and GitHub releases.
- **Assess before configuring.** Every project has different directory structures, dependencies, and type stub needs. Examine the codebase first.
- **Auto-fix first, then manual.** Let `ruff check --fix` handle the easy stuff. Only manually fix what's left.
- **Separate config commits from fix commits.** Makes PRs reviewable.
- **Pre-commit mypy must match local mypy.** Same stubs, same config. If they diverge, you'll get surprises.
- **The `disallow_untyped_defs = false` + `check_untyped_defs = true` combo** is the right starting point — it checks function bodies for type consistency without requiring annotations on every function signature. Tightening to `disallow_untyped_defs = true` is a future step once the codebase has better coverage.
