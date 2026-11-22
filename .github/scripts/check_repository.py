"""Validate tracked repository files without importing or running scenarios."""
from pathlib import Path
import json
import re
import subprocess
import tokenize
import tomllib
from urllib.parse import unquote, urlsplit

import yaml


def check_file(path: Path, root: Path) -> None:
    suffix = path.suffix.lower()
    if suffix == ".py":
        with tokenize.open(path) as source:
            compile(source.read(), str(path), "exec")
    elif suffix == ".json":
        json.loads(path.read_text(encoding="utf-8"))
    elif suffix == ".toml":
        with path.open("rb") as source:
            tomllib.load(source)
    elif suffix in {".yaml", ".yml"}:
        yaml.safe_load(path.read_text(encoding="utf-8"))
    elif suffix == ".md":
        text = path.read_text(encoding="utf-8")
        if path.name == "SKILL.md":
            match = re.match(r"\A---\n(.*?)\n---(?:\n|$)", text, re.S)
            if not match:
                raise ValueError("Missing skill YAML frontmatter")
            metadata = yaml.safe_load(match.group(1))
            if not isinstance(metadata, dict):
                raise ValueError("Skill metadata must be a mapping")
            if metadata.get("name") != path.parent.name:
                raise ValueError("Skill name does not match its directory")
            if not isinstance(metadata.get("description"), str):
                raise ValueError("Missing skill description")
        # External links and anchors are not fetched.
        for match in re.finditer(r"\]\((<[^>]+>|[^\s)]+)(?:\s+[\"'][^\"']*[\"'])?\)", text):
            href = match.group(1).strip("<>")
            url = urlsplit(href)
            if url.scheme or url.netloc or not url.path:
                continue
            target = (path.parent / unquote(url.path)).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Local link leaves repository: " + href)
            if not target.exists():
                raise ValueError("Missing local link target: " + href)


def main() -> int:
    root = Path.cwd().resolve()
    tracked = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    checked = 0
    failures = []
    for name in filter(None, tracked):
        path = root / name
        if not path.is_file():
            failures.append(name + ": tracked file is missing")
            continue
        if path.suffix.lower() not in {".py", ".json", ".toml", ".yaml", ".yml", ".md"}:
            continue
        try:
            check_file(path, root)
            checked += 1
        except (ValueError, SyntaxError, OSError, yaml.YAMLError) as error:
            failures.append(name + ": " + str(error))
    for failure in failures:
        print(failure)
    print(f"Static validation: {checked} files checked, {len(failures)} failures")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
