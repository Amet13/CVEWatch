# Maintainer skills

Skills for people and agents who work on this repository. The user skills are
in `skills/`.

`.claude/skills` is a symlink to this folder, so Claude Code finds them. Git
stores it as a symlink. On Windows without symlink support, git checks it out
as a small text file; the skills still work from `.agents/skills/`. To get the
link there, enable `core.symlinks` and developer mode, or copy this folder to
`.claude/skills/`.
