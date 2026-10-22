# RouteWarden CLI Versioning & Release Guide

This document explains how versioning is managed for the **RouteWarden CLI** (`rwarden`) repository (`github.com/routewarden/cli`).

---

## 1. Single Source of Truth (`version.json`)

The canonical release version of `rwarden` is stored in [`version.json`](version.json) at the repository root:

```json
{
  "version": "v5.3.2"
}
```

Whenever you prepare a release, update this file or use the automated synchronization script.

---

## 2. Automated Version Synchronization (`update-version.sh`)

When publishing a new release, version numbers must stay in sync across:

1. **`version.json`**: Canonical version tracking.
2. **`main.go`**: Runtime CLI version string (`var version = "5.3.0"`).
3. **`cmd/shipper/main.go`**: Standalone shipper micro-binary version string.
4. **`cmd/dashboard/main.go`**: Standalone dashboard micro-binary version string.
5. **`cmd/tcp-warden/main.go`**: Standalone Layer 4 proxy daemon version string.
6. **`proxy/plugins/sdk/sdk.go`**: RouteWarden Plugin SDK version (`const Version = "5.3.0"`).
7. **`observability/manager.go`**: Dashboard API response & engine version (`var Version = "5.3.0"`).
8. **`observability/custom_dashboard.go`**: SOC Dashboard HTML badges & core runtime tags.
9. **`observability/auth_screen.go`**: Terminal auth login screen banner.
10. **`engine/audit.go`**: SARIF security linter report metadata.
11. **`README.md`**: CLI output examples (`# rwarden version 5.3.0`).
12. **`VERSIONING.md`**: Canonical version tracking documentation.
13. **`Dockerfile*`**: Multi-stage build documentation headers (`Dockerfile`, `Dockerfile.dashboard`, `Dockerfile.shipper`, `Dockerfile.tcp-warden`).
14. **`observability/ingest_test.go` & `integration_test.go`**: Automated test suite assertions.
15. **Documentation Registry**: `docs/docs/version.json` and installer fallback when in RouteWarden monorepo.

> **Note**: The universal installer is maintained centrally and served directly at `https://routewarden.github.io/install.sh`.

To automate this across all files, run [`scripts/update-version.sh`](scripts/update-version.sh):

### Mode A: Pass target version via CLI

```bash
./scripts/update-version.sh v5.0.1
# or without 'v' prefix:
./scripts/update-version.sh 5.0.1
```

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
