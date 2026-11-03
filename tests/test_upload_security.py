"""Security boundary tests for uploaded JSON files."""
import os

import pytest

import src.ingestion as ingestion
from src.ingestion import FindingIngestionError, load_json_upload


@pytest.mark.skipif(os.name == "nt", reason="upload loader uses POSIX directory-relative file access")
def test_json_upload_rejects_symlink_resolving_outside_temp_directory(tmp_path, monkeypatch):
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    outside_file = tmp_path / "outside.json"
    outside_file.write_text('{"secret": "must not be read"}', encoding="utf-8")
    symlink = upload_root / "linked.json"
    try:
        symlink.symlink_to(outside_file)
    except (NotImplementedError, OSError) as exc:
        pytest.skip("symlink creation is unavailable: %s" % exc)

    monkeypatch.setattr(ingestion.tempfile, "gettempdir", lambda: str(upload_root))

    with pytest.raises(FindingIngestionError, match="Invalid upload path"):
        load_json_upload(str(symlink))
