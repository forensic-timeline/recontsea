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

## Installation

  1. **Clone the Repository**

      ```bash
      git clone https://github.com/forensic-timeline/recontsea
      ```

  2. **Install Depedencies**

      ```bash
      cd recontsea
      pip install -r requirements.txt
      ```

## How to Run

To ensure that the installation is correct and the code is functioning as expected, you can run by:

```bash
python main.py 
```

example:

```bash
python main.py 1sample
```

ensure you have the dataset in /dataset and already make directory in /results/<dataset_name>

## Output

The tool generates several files to aid in analysis:
### Event Reconstruction Process
1. Normalization
2. Log Decoder
3. Low Level Predict
4. High Level Predict

### Evaluation Process
1. Low Level Ground Truth
2. Low Level Evaluation
3. High Level Ground Truth
4. High Level Evaluation

all output will be stored in /results/<dataset_name>