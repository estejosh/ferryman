# Push instructions — publishing ferry-deadman

The owner creates the GitHub repository, then pushes this repo. Run from
`/mnt/x/golive-proposals/ferry-deadman/repo`:

```sh
gh repo create estejosh/ferry-deadman --public --source . --remote origin --push
```

If the remote already exists but isn't wired up:

```sh
git remote add origin git@github.com:estejosh/ferry-deadman.git
git push -u origin main
```

## After the first push

1. Enable branch protection on `main` (require PRs, or at minimum linear
   history) — optional for a solo project.
2. Publish to crates.io (owner's API token required):

   ```sh
   cargo publish --dry-run
   cargo publish
   ```

3. Optional release tag:

   ```sh
   git tag -a v0.1.0 -m "ferry-deadman 0.1.0 — first sealed breath"
   git push origin v0.1.0
   ```

4. Verify CI-less basics on a clean machine:

   ```sh
   cargo install --git https://github.com/estejosh/ferry-deadman ferry-deadman
   ferry-deadman --version
   ```
