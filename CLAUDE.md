<!-- ferry:git begin -->
## Git: Forgejo first

- `origin` is Forgejo (`forgejo:estejosh/ferryman.git`, Josh's git server on grouchly). Fetch from it, branch from it, push to it. Pull requests and merges happen on Forgejo.
- GitHub is a copy. A relay on grouchly copies every branch and tag from Forgejo to GitHub within a minute or two. Never push to GitHub, never open or merge a pull request there, never change anything on GitHub.
- GitHub CI still runs on that copy. When it fails, a Ferryman order (or a Forgejo issue, where the repo has no channel) is opened with the error. Fix it here and push to Forgejo.
- If `origin` on your machine still points at GitHub: `git remote rename origin github && git remote add origin forgejo:estejosh/ferryman.git && git fetch origin`. The `forgejo` ssh alias exists on beastly and grouchly; anywhere else, ask in the ferryman channel.
<!-- ferry:git end -->
