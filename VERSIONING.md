# RouteWarden CLI Versioning & Release Guide

This document explains how versioning is managed for the **RouteWarden CLI** (`rwarden`) repository (`github.com/routewarden/cli`).

---

## 1. Single Source of Truth (`version.json`)

The canonical release version of `rwarden` is stored in [`version.json`](version.json) at the repository root:

```json
{
  "version": "v1.0.0"
}
```

Whenever you prepare a release, update this file or use the automated synchronization script.

---

## 2. Automated Version Synchronization (`update-version.sh`)

When publishing a new release, version numbers must stay in sync across:
1. **`version.json`**: Canonical version tracking.
2. **`main.go`**: Runtime CLI version string (`var version = "1.0.0"`).
3. **`package.json`**: Node / VitePress documentation package version.
4. **`install.sh`**: Fallback release tag (`LATEST_TAG="v1.0.0"`).
5. **`docs/public/install.sh`**: Hosted installer script fallback.
6. **`README.md`**: CLI output examples (`# rwarden version 1.0.0`).
7. **`docs/index.md`**: CLI portal documentation examples.

To automate this across all files, run [`scripts/update-version.sh`](scripts/update-version.sh):

### Mode A: Pass target version via CLI
```bash
./scripts/update-version.sh v1.1.0
```
*(or via npm script: `npm run version:update v1.1.0`)*

### Mode B: Read directly from `version.json`
Edit [`version.json`](version.json) manually, then run:
```bash
./scripts/update-version.sh
```

---

## 3. Step-by-Step Release Workflow

### Step 1: Run Quality Checks & Tests
Verify all Go tests pass with race detection:
```bash
go test -v -race ./...
```

### Step 2: Synchronize Version
```bash
./scripts/update-version.sh v1.1.0
```

### Step 3: Review Diff & Commit
```bash
git diff
git commit -am "chore: release v1.1.0"
```

### Step 4: Tag & Push
GoReleaser and GitHub Actions trigger on pushed tags prefixed with `v`:
```bash
git tag v1.1.0
git push origin main --tags
```

Once pushed, GitHub Actions automatically:
- Builds multi-platform binaries with GoReleaser (Linux, macOS, Windows on `amd64` and `arm64`).
- Creates a new GitHub Release with binary archives and checksums.
- Builds and publishes the multi-architecture container image to `ghcr.io/routewarden/cli:latest` and `ghcr.io/routewarden/cli:v1.1.0`.
