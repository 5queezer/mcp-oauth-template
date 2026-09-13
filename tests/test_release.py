"""Release publication must fail closed and target the tested commit."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release.py"


def load_release():
    assert SCRIPT.exists(), "Release publisher is missing"
    spec = importlib.util.spec_from_file_location("release", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_publish_targets_tested_commit(monkeypatch):
    release = load_release()
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if "--paginate" in args:
            return subprocess.CompletedProcess(args, 0, "v0.2.1\n")
        return subprocess.CompletedProcess(args, 0, "[]")

    monkeypatch.setattr(release.subprocess, "run", run)
    release.publish("0.3.1", "owner/repo", "a" * 40)
    assert calls[-2] == [
        "gh",
        "api",
        "repos/owner/repo/git/refs",
        "--method",
        "POST",
        "-f",
        "ref=refs/tags/v0.3.1",
        "-f",
        "sha=" + "a" * 40,
    ]
    assert calls[-1] == [
        "gh",
        "release",
        "create",
        "v0.3.1",
        "--repo",
        "owner/repo",
        "--verify-tag",
        "--title",
        "v0.3.1",
        "--generate-notes",
    ]


def test_existing_release_is_noop(monkeypatch):
    release = load_release()
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "v0.3.1\nv0.2.1\n")

    monkeypatch.setattr(release.subprocess, "run", run)
    release.publish("0.3.1", "owner/repo", "a" * 40)
    assert len(calls) == 1
    assert calls[0][:2] == ["gh", "api"]


def test_lookup_error_does_not_publish(monkeypatch):
    release = load_release()

    def run(args, **kwargs):
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(release.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        release.publish("0.3.1", "owner/repo", "a" * 40)


def test_remote_conflicting_tag_does_not_publish(monkeypatch):
    release = load_release()

    def run(args, **kwargs):
        assert args[:2] == ["gh", "api"], "Must not publish a conflicting tag"
        if "--paginate" in args:
            return subprocess.CompletedProcess(args, 0, "")
        refs = [{"ref": "refs/tags/v0.3.1", "object": {"type": "commit", "sha": "b" * 40}}]
        return subprocess.CompletedProcess(args, 0, json.dumps(refs))

    monkeypatch.setattr(release.subprocess, "run", run)
    with pytest.raises(ValueError, match="different commit"):
        release.publish("0.3.1", "owner/repo", "a" * 40)


@pytest.mark.parametrize("version", ["", "0.3", "0.3.1rc1", "v0.3.1", "0.3.1;echo bad"])
def test_invalid_version_does_not_call_github(version, monkeypatch):
    release = load_release()

    def run(*args, **kwargs):
        pytest.fail("Invalid versions must not call external commands")

    monkeypatch.setattr(release.subprocess, "run", run)
    with pytest.raises(ValueError, match="version"):
        release.publish(version, "owner/repo", "a" * 40)


def test_existing_tag_on_tested_commit_can_be_released(monkeypatch):
    release = load_release()
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if "--paginate" in args:
            return subprocess.CompletedProcess(args, 0, "")
        assert "POST" not in args, "Existing matching tags must not be recreated"
        refs = [{"ref": "refs/tags/v0.3.1", "object": {"type": "commit", "sha": "a" * 40}}]
        return subprocess.CompletedProcess(args, 0, json.dumps(refs))

    monkeypatch.setattr(release.subprocess, "run", run)
    release.publish("0.3.1", "owner/repo", "a" * 40)
    assert calls[-1][:4] == ["gh", "release", "create", "v0.3.1"]


def test_publish_failure_is_reported(monkeypatch):
    release = load_release()

    def run(args, **kwargs):
        if args[:2] == ["gh", "api"]:
            return subprocess.CompletedProcess(args, 0, "" if "--paginate" in args else "[]")
        assert kwargs["check"] is True
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(release.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        release.publish("0.3.1", "owner/repo", "a" * 40)


def test_tag_creation_conflict_does_not_publish(monkeypatch):
    release = load_release()

    def run(args, **kwargs):
        assert args[:2] == ["gh", "api"], "Must not publish after tag creation fails"
        if "POST" in args:
            assert kwargs["check"] is True
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, "" if "--paginate" in args else "[]")

    monkeypatch.setattr(release.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        release.publish("0.3.1", "owner/repo", "a" * 40)
