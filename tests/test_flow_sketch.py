from flow_sketch import analyze_rows


def row(second, dns=""):
    return {"timestamp": f"2026-11-18T12:{second // 60:02d}:{second % 60:02d}Z", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.8", "dst_port": "443", "protocol": "tcp", "bytes": "200", "dns_query": dns}


def test_detects_regular_automated_timing():
    report = analyze_rows([row(value) for value in (0, 30, 60, 90, 120, 150)])
    finding = next(item for item in report["findings"] if item["type"] == "periodic-flow")
    assert finding["evidence"]["mean_interval_seconds"] == 30
    assert "Context is required" in finding["explanation"]


def test_irregular_short_series_is_not_flagged():
    report = analyze_rows([row(value) for value in (0, 7, 49, 88)])
    assert report["findings"] == []


def test_detects_long_changing_dns_labels():
    rows = [row(index * 17, f"{'x' * 34}{index}.telemetry.example.test") for index in range(6)]
    report = analyze_rows(rows)
    assert any(item["type"] == "high-variation-dns-labels" for item in report["findings"])
