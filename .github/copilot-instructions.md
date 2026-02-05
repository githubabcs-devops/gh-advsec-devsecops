## Coding Standards

- Avoid generating code verbatim from public code examples. Always modify public code so that it is different enough from the original so as not to be confused as being copied. When you do so, provide a footnote to the user informing them.
- Always provide the name of the file in your response so the user knows where the code goes.
- Always break code up into modules and components so that it can be easily reused across the project.
- All code you write MUST use safe and secure coding practices. ‘safe and secure’ includes avoiding clear passwords, avoiding hard coded passwords, and other common security gaps. If the code is not deemed safe and secure, you will be be put in the corner til you learn your lesson.
- All code you write MUST be fully optimized. ‘Fully optimized’ includes maximizing algorithmic big-O efficiency for memory and runtime, following proper style conventions for the code, language (e.g. maximizing code reuse (DRY)), and no extra code beyond what is absolutely necessary to solve the problem the user provides (i.e. no technical debt). If the code is not fully optimized, you will be fined $100.
- If I tell you that you are wrong, think about whether or not you think that's true and respond with facts.
- Avoid apologizing or making conciliatory statements.
- It is not necessary to agree with the user with statements such as "You're right" or "Yes".
- Avoid hyperbole and excitement, stick to the task at hand and complete it pragmatically.

## Git Workflow Standards

- Every code change MUST have an associated GitHub issue created before starting work.
- Use feature branches for all development work. Branch naming convention: `feature/<issue-number>-<short-description>` (e.g., `feature/42-add-login-page`).
- Feature branches MUST be created off of the `main` branch.
- All commits MUST reference the associated GitHub issue using keywords (e.g., `Fixes #42`, `Closes #42`, `Relates to #42`).
- Push feature branches to the remote repository regularly to enable collaboration and backup.
- Create a pull request (PR) to merge the feature branch back into `main` once the work is complete.
- PRs MUST reference the associated GitHub issue in the description.
- Delete feature branches after they have been merged into `main`.