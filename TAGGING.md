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

Create a tag locally:

```bash
git tag v2.0.0
```

Push the tag to `origin`:

```bash
git push origin v2.0.0
```

Other examples:

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