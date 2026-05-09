# recontsea
## TSEA: Temporal-Semantic Event Aggregation for Forensic Web Attack Reconstruction

A forensic event reconstruction tool that transforms low-level web server log events into concise high-level attack narratives using temporal adjacency and semantic similarity. TSEA integrates log decoding, Sigma rule-based anomaly detection, and temporal-semantic aggregation to reconstruct multi-step web attack sequences from heterogeneous log artifacts (access.log, error.log, auth.log, syslog).

## Features:
- URL and payload decoding (Base64, Hex, XOR, ROT13)
- Adapted Sigma rules for post-incident forensic analysis
- High-level event aggregation based on temporal and semantic criteria