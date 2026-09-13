"""Publish the package version as a GitHub release after CI succeeds."""

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path


def publish(version: str, repository: str, commit: str) -> None:
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("Release version must use stable major.minor.patch format")
    tag = f"v{version}"
    releases = subprocess.run(
        ["gh", "api", f"repos/{repository}/releases", "--paginate", "--jq", ".[].tag_name"],
        check=True,
        capture_output=True,
        text=True,
    )
    if tag in releases.stdout.splitlines():
        print(f"Release {tag} already exists. Nothing to publish.")
        return

    # Inspect GitHub directly: tags in the CI checkout can be stale.
    refs = subprocess.run(
        ["gh", "api", f"repos/{repository}/git/matching-refs/tags/{tag}"],
        check=True,
        capture_output=True,
        text=True,
    )
    existing = next(
        (ref for ref in json.loads(refs.stdout) if ref["ref"] == f"refs/tags/{tag}"), None
    )
    if existing is not None:
        if existing["object"]["type"] != "commit" or existing["object"]["sha"] != commit:
            raise ValueError(f"Tag {tag} is annotated or points to a different commit")
    else:
        # Creation is atomic. A concurrent creator causes failure, not reassignment.
        subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repository}/git/refs",
                "--method",
                "POST",
                "-f",
                f"ref=refs/tags/{tag}",
                "-f",
                f"sha={commit}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    subprocess.run(
        [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repository,
            "--verify-tag",
            "--title",
            tag,
            "--generate-notes",
        ],
        check=True,
    )


if __name__ == "__main__":
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    publish(
        metadata["project"]["version"], os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    )
