# Wiki Source Files

This folder now stores the project documentation in GitHub Wiki-friendly page names.

## Publish to the GitHub Wiki repository

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
