# AWS Scripts

Quick setup instructions for creating an isolated Python environment and running scripts in this directory.

## 1. Create and activate a virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt  # add packages needed by the scripts you plan to run
```

## 2. Run a script
From the repo root (venv still active), invoke the script you need with Python:
```bash
python aws-scripts/path/to_script.py [optional arguments]
for example:
python aws-scripts/cost-optimization/check_cost_anomaly_enabled.py --profile princeton-production --output summary
```

That’s it—deactivate the environment with `deactivate` when you’re done.
