"""A throwaway git upstream with controllable commit dates, for dataset tests."""

import os
import subprocess
from pathlib import Path


class Origin:
    """A throwaway upstream repository with controllable commit dates."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir()
        self.run("init", "--quiet", "--initial-branch=main")
        self.run("config", "uploadpack.allowFilter", "true")
        self.tick = 0

    def run(self, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        if self.__dict__.get("tick") is not None:
            stamp = f"2024-01-{1 + self.tick:02d}T00:00:00+00:00"
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = stamp
        return subprocess.run(["git", "-C", str(self.root), *args], env=env,
                              capture_output=True, text=True, check=True).stdout.strip()

    def commit(self, files: dict[str, str], message: str) -> str:
        for rel, text in files.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        self.run("add", "-A")
        self.tick += 1
        self.run("commit", "--quiet", "-m", message)
        return self.run("rev-parse", "HEAD")

    @property
    def url(self) -> str:
        return self.root.resolve().as_uri()
