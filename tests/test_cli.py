"""CLI-level tests.

These import ``graphgate.cli`` with no provider SDK installed, which is itself
part of the contract: replaying an archived trace must not require one.
"""

import pytest

from graphgate.cli import build_parser, main


def test_replay_via_cli_reproduces_the_source(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["readability", "optimize"],
        [file_block("v = 2"), file_block("v = 3")],
    )
    out = tmp_path / "replayed.jsonl"

    assert main(["--replay", str(source), "--out", str(out)]) == 0
    assert out.read_bytes() == source.read_bytes()


def test_replay_refuses_to_write_onto_its_source(
    snapshot_dir, tmp_path, file_block, record_live
):
    """The writer appends, so this would corrupt the recording."""
    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [file_block("v = 2")]
    )
    before = source.read_bytes()

    with pytest.raises(SystemExit, match="must differ from --replay"):
        main(["--replay", str(source), "--out", str(source)])

    assert source.read_bytes() == before


def test_live_run_requires_its_own_flags(tmp_path):
    with pytest.raises(SystemExit, match="--snapshot, --prompts, --trace-id"):
        main(["--out", str(tmp_path / "t.jsonl")])


def test_replay_does_not_need_the_live_flags():
    args = build_parser().parse_args(["--replay", "t.jsonl", "--out", "o.jsonl"])
    assert args.snapshot is None
    assert args.prompts is None
    assert args.trace_id is None


def test_prompts_file_skips_blanks_and_comments(tmp_path):
    from graphgate.cli import _load_prompts

    path = tmp_path / "prompts.txt"
    path.write_text(
        "# ISTAS 2025 protocol\nimprove readability\n\n  optimize  \n",
        encoding="utf-8",
    )
    assert _load_prompts(path) == ("improve readability", "optimize")


def test_prompts_file_must_not_be_empty(tmp_path):
    from graphgate.cli import _load_prompts

    path = tmp_path / "prompts.txt"
    path.write_text("# only a comment\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no prompts found"):
        _load_prompts(path)


def test_seeds_are_parsed_as_a_list(tmp_path):
    args = build_parser().parse_args(
        ["--out", "o.jsonl", "--snapshot", "s", "--prompts", "p", "--trace-id", "x",
         "--seeds", "0,1,2,3"]
    )
    assert args.seeds == (0, 1, 2, 3)


def test_seeds_reject_non_integers():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--out", "o.jsonl", "--seeds", "a,b"])
