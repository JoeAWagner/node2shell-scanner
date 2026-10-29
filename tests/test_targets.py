from pathlib import Path

from n2scan.targets import is_private, load_targets


def test_load_csv_with_header(tmp_path: Path):
    f = tmp_path / "t.csv"
    f.write_text("name,url,owner\nweb1,https://a.sbu.edu,alice\nweb2,b.sbu.edu,bob\n")
    targets = load_targets(f)
    assert [t.host for t in targets] == ["a.sbu.edu", "b.sbu.edu"]
    # scheme added when missing
    assert targets[1].url == "https://b.sbu.edu"
    # extra columns preserved
    assert targets[0].meta["owner"] == "alice"


def test_load_plain_list_and_comments(tmp_path: Path):
    f = tmp_path / "t.txt"
    f.write_text("# fleet list\nhttps://a.sbu.edu\n\n# skip me\nb.sbu.edu\n")
    targets = load_targets(f)
    assert [t.host for t in targets] == ["a.sbu.edu", "b.sbu.edu"]


def test_dedupes_by_host(tmp_path: Path):
    f = tmp_path / "t.txt"
    f.write_text("a.sbu.edu\nhttps://a.sbu.edu\na.sbu.edu\n")
    targets = load_targets(f)
    assert len(targets) == 1


def test_is_private():
    assert is_private("10.0.0.1")
    assert is_private("127.0.0.1")
    assert not is_private("8.8.8.8")
    assert not is_private("a.sbu.edu")
