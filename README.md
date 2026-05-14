# recontsea

## Prerequisites

- Python 3.13 or higher
- Git
- Python virtual environment (venv or conda)

## Python Virtual Environment Setup

Here is a simple example of how to create and activate a virtual environment:

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
