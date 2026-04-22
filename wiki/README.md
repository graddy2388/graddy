# Wiki Source Files

This folder stores the project documentation in GitHub Wiki-friendly page names.

## Automatic publishing (recommended)

This repository includes `.github/workflows/wiki-sync.yml`, which publishes changes from `wiki/` to the GitHub Wiki repository (`<repo>.wiki.git`) on every push to `main` (and `claude/**`) that touches wiki files.

If the **Wiki** tab is still empty, ensure the repository Wiki feature is enabled and run the workflow manually from the **Actions** tab.

## Manual publishing (fallback)

GitHub wikis are backed by a separate repository named `<repo>.wiki.git`.

```bash
git clone https://github.com/graddy2388/graddy.wiki.git /tmp/graddy.wiki
rsync -av --delete wiki/ /tmp/graddy.wiki/
cd /tmp/graddy.wiki
git add .
git commit -m "Sync wiki pages from main repository"
git push origin master
```

After pushing, the pages appear under the **Wiki** tab on GitHub.
