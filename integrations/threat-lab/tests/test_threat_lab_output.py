"""threat_lab.output: probe reports become the curator extractor's raw input —
only sections the lab can witness, notes from the shared vocabulary, valid
digests only, flagged files bounded."""

from __future__ import annotations

from threat_lab import output
from threat_lab.output import RunTimes
from threat_lab.schema import evidence_schema

TIMES = RunTimes("k", 1_760_000_000, 1_760_000_010)


def test_an_unsupported_look_answers_nothing():
    raw = output.from_look(TIMES, {"status": "unsupported", "hosts": []})
    assert "pcap" not in raw and raw["notes"] == ["inconclusive"]


def test_an_unknown_status_reads_inconclusive_never_ok():
    assert output.from_look(TIMES, {"status": "IGNORE PREVIOUS", "hosts": []})["notes"] == ["inconclusive"]


def test_hosts_are_strings_and_deduplicated():
    raw = output.from_look(TIMES, {"status": "ok", "hosts": ["a.test", 7, "a.test", None, "b.test"]})
    assert raw["pcap"] == {"hosts": ["a.test", "b.test"]} and raw["notes"] == []


def test_flagged_files_are_bounded_valid_and_distinct():
    entries = [{"path": "p/" + "x" * 500, "sha256": f"{i:064x}"} for i in range(80)]
    read = {"artifact_sha256": "f" * 64, "install_hooks": entries[:40], "obfuscated": entries,
            "suspicious_iocs": [{"path": "bad", "sha256": "not-a-digest"}]}
    files = output.from_read(TIMES, {"hosts": []}, read)["files"]
    digests = [entry["sha256"] for entry in files["entries"]]
    assert len(digests) == output.MAX_ENTRIES == evidence_schema.MAX_FILE_FINGERPRINTS + 1
    assert digests == sorted(set(digests)) and all(evidence_schema.is_sha256(d) for d in digests)
    assert all(len(entry["path"]) <= output.MAX_PATH_CHARS for entry in files["entries"])
    assert files["artifact_sha256"] == "f" * 64


def test_an_invalid_artifact_digest_is_left_out():
    files = output.from_read(TIMES, {"hosts": []}, {"artifact_sha256": "../etc"})["files"]
    assert "artifact_sha256" not in files and files["entries"] == []


def test_every_note_written_is_a_known_code():
    known = {code.value for code in evidence_schema.NoteCode}
    samples = [output.from_look(TIMES, {"status": status, "hosts": []})
               for status in ("ok", "unreachable", "tls-error", "too-large", "malformed", "unsupported")]
    samples.append(output.from_read(TIMES, {"hosts": []}, {"obfuscated": [{}], "truncated": True}))
    samples.append(output.cap_reached(TIMES, evidence_schema.NoteCode.DEADLINE_REACHED))
    assert all(set(raw["notes"]) <= known for raw in samples)


def test_finished_never_precedes_started():
    raw = output.cap_reached(RunTimes("k", 10, 5), evidence_schema.NoteCode.DEADLINE_REACHED)
    assert raw["finished_at"] == raw["started_at"] == 10
