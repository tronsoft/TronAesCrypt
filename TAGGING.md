# Tagging

This repository uses Git tags with a `v` prefix.
# Tagging

This repository uses Git tags with a `v` prefix.

## Current release tag

The current release tag is `v2.0.0`.

That tag is valid and may be used for this release.

## Recommended tag format going forward

Use full semantic version style for releases and prereleases:

- `vMAJOR.MINOR.PATCH`
- `vMAJOR.MINOR.PATCH-label`

Examples:

- `v2.0.0`
- `v2.0.1`
- `v2.0.1-prerelease`
- `v2.1.0-rc1`

## Why this format is required

Short tags such as `v2.0` become ambiguous once patch and prerelease tags exist. Using `vMAJOR.MINOR.PATCH` for normal releases makes the sequence explicit and keeps prerelease naming consistent.

## Release steps

Releases are automated via GitHub Actions. When you push a tag matching `v{MAJOR}.{MINOR}.{PATCH}[-prerelease]`, the workflow:

1. Validates the tag format
2. Extracts the version (e.g., `v2.0.0` → `2.0.0`)
3. Builds the project with the derived version
4. Packs the NuGet package
5. Creates a GitHub Release with the `.nupkg` artifact

### Creating a release

Create and push a tag locally:

```bash
git tag v2.0.0
git push origin v2.0.0
```

### GitHub Actions will then:

- Extract version `2.0.0` from the tag
- Pack `TRONSoft.TronAesCrypt.Core.2.0.0.nupkg`
- Create a GitHub Release with the package attached
- Mark prerelease tags (e.g., `v2.0.0-rc1`) as prerelease releases

### After the workflow completes

1. Check the [GitHub Actions](../../actions) tab to verify the workflow succeeded
2. Visit the [Releases](../../releases) page to see the new release
3. Add manual release notes on GitHub if desired (edit the release to add description, highlights, breaking changes, etc.)
4. The `.nupkg` artifact is available for download from the release

### Other examples

```bash
git tag v2.0.1
git push origin v2.0.1
```

```bash
git tag v2.0.1-prerelease
git push origin v2.0.1-prerelease
```

## Verify tags

List local tags:

```bash
git tag -l
```

Show a specific tag:

```bash
git show v2.0.0
```

Check tags on the remote:

```bash
git ls-remote --tags origin
```

## Notes

This document describes Git tag naming only.

The library and assembly version metadata in the project files may use a different format, such as `2.0.0.0`.