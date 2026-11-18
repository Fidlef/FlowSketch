# FlowSketch

FlowSketch finds explainable patterns in network-flow metadata without capturing
packets or inspecting payload content. It highlights very regular connection
timing and long, changing DNS labels while explicitly preserving benign
explanations such as telemetry, monitoring, and update checks.

```bash
python flow_sketch.py demo/synthetic-flows.csv
python -m pytest -q
```

All demo addresses use documentation-only IP ranges and `.test` domains. Use
the tool only with authorized metadata. A finding means “review this pattern,”
not “this host is compromised.” NAT, missing records, clock problems, normal
automation, and small samples can all distort results.

## AI-assisted authorship

OpenAI Codex generated the initial implementation, tests, synthetic dataset,
and documentation. The owner must review and understand it before describing a
personal contribution.
