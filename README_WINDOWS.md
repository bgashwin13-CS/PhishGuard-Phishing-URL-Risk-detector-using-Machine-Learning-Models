# PhishGuard ML — Windows Local Web Prototype

This project implements the paper's URL-only phishing screening workflow with Random Forest, XGBoost, calibrated probabilities, and a 0–100 risk score. It is a local Flask website and does not intentionally open the submitted destination URL.

## 1. Install once
Install **Python 3.11 (64-bit)** and **VS Code**. During Python installation select **Add Python to PATH**.

## 2. Open in VS Code
Extract this ZIP. In VS Code choose **File > Open Folder** and select `PhishGuard_Web_Prototype`.

## 3. Create the environment
Double-click `setup_windows.bat`, or run it from the VS Code terminal. It creates `.venv` and installs all required Python packages.

## 4. Train the publication models
Double-click `train_windows.bat`. Internet is required for this first training because the script retrieves the official UCI PhiUSIIL dataset (ID 967). It then derives URL-only features, performs the paper's stratified 80/20 split with random state 42, trains calibrated Random Forest and XGBoost models, and writes real metrics to `reports/metrics.json`.

Training may take time because the dataset is large. Do not close the terminal while it is training.

## 5. Run the local website
Double-click `run_windows.bat`. Your browser opens:

`http://127.0.0.1:5000`

Enter a URL and press **Analyze URL**. The website shows the combined 0–100 display score, risk band, separate Random Forest and XGBoost phishing probabilities, model latency, and the locally extracted URL features.

## 6. What to show during the project demo
Show the folder in VS Code, `src/features.py`, `src/train.py`, the two files in `models/`, `reports/metrics.json`, and then run the webpage. Explain that the URL-only primary detector does not fetch the destination webpage.

## Project structure
```
PhishGuard_Web_Prototype/
  app.py
  requirements.txt
  setup_windows.bat
  train_windows.bat
  run_windows.bat
  src/
    __init__.py
    features.py
    train.py
  templates/
    index.html
  static/
    style.css
    app.js
  models/        # generated after training
  reports/       # generated after training
  data/
```

## Important publication note
The website averages the two calibrated model probabilities only for the combined display score. The paper's RF-vs-XGBoost comparison should continue to report each model separately. Use only the real values generated in `reports/metrics.json`; do not invent experimental results.
