# One-time helper: refresh app/data from a sibling source folder if needed.
# Prefer keeping all runtime files already under app/data.
$ErrorActionPreference = "Stop"
Write-Host "Runtime artifacts should already be under app/data."
Write-Host "Expected:"
Write-Host "  data/models/*.pt"
Write-Host "  data/prepared_graphs/test_graphs.pt"
Write-Host "  data/test_edges_5min_enriched.parquet"
Write-Host "  data/rag_input/gnn_test_events_evaluation.jsonl"
Get-ChildItem -Recurse (Join-Path $PSScriptRoot "..\data") | Select-Object FullName, Length
