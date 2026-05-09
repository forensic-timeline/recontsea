# recontsea
## TSEA: Temporal-Semantic Event Aggregation for Forensic Web Attack Reconstruction

A forensic event reconstruction tool that transforms low-level web server log events into concise high-level attack narratives using temporal adjacency and semantic similarity. TSEA integrates log decoding, Sigma rule-based anomaly detection, and temporal-semantic aggregation to reconstruct multi-step web attack sequences from heterogeneous log artifacts (access.log, error.log, auth.log, syslog).

## Features:

- URL and payload decoding (Base64, Hex, XOR, ROT13)
- Adapted Sigma rules for post-incident forensic analysis
- High-level event aggregation based on temporal and semantic criteria

## Prerequisites

- Python 3.13 or higher
- Git
- Python virtual environment (venv or conda)

## Python Virtual Environment Setup

TSEA uses several Python packages to function properly. It is recommended to install the package in a virtual environment to avoid dependency conflicts. Here is a simple example of how to create and activate a virtual environment:

  1. Anaconda or Miniconda

      ```bash
      conda create --name recontsea python=3.13
      conda activate recontsea
      ```

Or using venv:

  2. Venv

      ```bash
      python -m venv venv
      source venv/bin/activate
      ```