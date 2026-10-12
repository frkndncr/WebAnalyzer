# Releasing

A release publishes three things from one tag: the GitHub release, the PyPI
package (`publish-pypi.yml`, Trusted Publishing) and the GitHub Action.

## Cut a release

1. Bump `VERSION` in `utils/version.py` and add a section to `CHANGELOG.md`.
2. Merge to `main` and wait for CI to pass.
3. Tag and create the release:

   ```bash
   git tag v3.7.1 && git push origin v3.7.1
   gh release create v3.7.1 --title "v3.7.1" --notes-file notes.md
   ```

   Publishing the release triggers the PyPI upload.

## Publish the Action on the GitHub Marketplace

Only the repository owner can do this, once:

1. Open the release on GitHub and click **Edit**.
2. Tick **Publish this Action to the GitHub Marketplace**. GitHub reads the
   name, description and branding from `action.yml`.
3. Accept the *GitHub Marketplace Developer Agreement* (first time only), pick
   the categories (*Security*, *Code quality*) and save.

`tests/test_action_metadata.py` guards what the Marketplace requires: a name,
a description of at most 125 characters, branding, documented inputs.

## Version tags for the Action

Users pin `@v3.7.0` (exact) or a moving major tag `@v3`. After a release you
may move the major tag so `@v3` follows the newest 3.x:

```bash
git tag -f v3 v3.7.1 && git push -f origin v3
```

Never move an exact `vX.Y.Z` tag.
