"""Level 4's raw output (output.from_run) and the host traffic reader
(traffic.read_pcap), build item LR3: a "no" is written only where the lab
witnessed it (LES-011), and an attacker-shaped recording never breaks the reader."""

from __future__ import annotations

from threat_lab import fixtures, output
from threat_lab.output import RunTimes
from threat_lab.traffic import is_recording, read_pcap

_TIMES = RunTimes("k", 1, 2)


def test_bait_not_seen_is_never_written_as_not_sent():
    raw = output.from_run(_TIMES, {"status": "ok", "processes": [],
                                   "traffic": {"hosts": ["a.example"], "bait_seen": False}})
    assert raw["pcap"] == {"hosts": ["a.example"]} and raw["processes"] == []


def test_a_failed_install_is_inconclusive_and_claims_no_processes():
    raw = output.from_run(_TIMES, {"status": "install-failed", "traffic": {"hosts": ["registry.npmjs.org"]}})
    assert raw["notes"] == ["inconclusive"] and "processes" not in raw


def test_process_entries_the_extractor_would_refuse_are_dropped():
    raw = output.from_run(_TIMES, {"status": "ok", "processes": [{"name": "sh", "phase": "boot"},
                                                                  {"name": 7, "phase": "run"},
                                                                  {"name": "x" * 500, "phase": "run"}]})
    assert raw["processes"] == [{"name": "x" * output.MAX_PROCESS_NAME_CHARS, "phase": "run"}]


def test_the_recording_reader_survives_garbage():
    assert not is_recording(b"") and read_pcap(b"\x00" * 100, "172.30.4.10").hosts == ()
    truncated = fixtures.fixture_install_recording()[:300]
    assert isinstance(read_pcap(truncated, "172.30.4.10").hosts, tuple)
    hostile = fixtures.pcap([fixtures.udp_frame("172.30.4.10", "1.1.1.1", 1, 53,
                                                b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c")])
    assert read_pcap(hostile, "172.30.4.10").hosts == ()            # a self-pointing name loops no further


def test_only_the_guests_own_traffic_counts():
    inbound = fixtures.pcap([fixtures.tcp_frame("198.51.100.9", "172.30.4.10", 443, 5000, b"", syn=True)])
    assert read_pcap(inbound, "172.30.4.10").hosts == ()
