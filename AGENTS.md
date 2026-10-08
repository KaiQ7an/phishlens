# PhishLens working instructions

- Work on PhishLens only unless the user explicitly expands the scope.
- Keep the current analyzer offline. Do not open email links, execute or save
  attachments, connect to a real inbox, or add real email fixtures.
- Update the README when changing installation, CLI behavior, scoring, or scope.
- This machine may reapply hidden flags to `.pth` files. Use a regular package
  installation instead of an editable installation, and reinstall after source
  changes before testing the installed CLI.
- After completing each batch of work, run relevant checks, commit the finished
  changes, and push to the configured GitHub remote. The user has authorized this
  workflow; do not ask for permission again for routine commits and pushes.
- Prefer small, coherent commits. Keep an individual fix with its regression
  tests; separate CI, packaging, and documentation updates when practical.
- Formal release is deferred while polishing. Routine commit/push batches must
  not create version tags, GitHub Releases, or PyPI uploads. Complete final
  acceptance review before starting a separate formal-release step.
- If the remote or authentication is unavailable, finish and commit local work,
  then report the precise connection requirement. Do not claim a push succeeded.
- Author commits as `KaiQian Xue <kaiqianxue593@gmail.com>` and do not add AI
  attribution or Co-Authored-By trailers. Do not rewrite existing commit history
  or force-push unless explicitly requested.
