# PhishGuard

## Real-Time Phishing URL Detection Risk Scoring using Random Forest and XGBoost an Machine Learning approach

PhishGuard is a machine-learning-based web application designed to analyze URLs and estimate whether they are **legitimate or potentially phishing**.

Instead of relying on a predefined list of malicious URLs, PhishGuard extracts lexical and structural characteristics from the URL entered by the user and sends these features to trained **Random Forest** and **XGBoost** models.

The resulting phishing probability is converted into an easy-to-understand **0–100 risk score**.

---

##  Objective

The objective of PhishGuard is to provide fast URL-based phishing detection without intentionally visiting the destination webpage.

The system is designed to accept previously unseen URLs and analyze their characteristics in real time.

---

##  How PhishGuard Works

User enters a URL

↓  

URL is normalized and parsed

↓  

22 structural URL features plus character TF-IDF features are extracted

↓  

Random Forest + XGBoost analyze the combined TF-IDF and structural features

↓  

Phishing probability is generated

↓  

Probability is converted into a 0–100 risk score

↓  

Risk level is displayed to the user

---

##  Machine Learning Models

### Random Forest

Random Forest uses multiple decision trees and combines their predictions to classify the URL.

**Configuration:**
- 300 decision trees
- Balanced subsampling
- Random state: 42

### XGBoost

XGBoost builds decision trees sequentially, where later trees improve the errors of the existing ensemble.

**Configuration:**
- 350 estimators
- Maximum depth: 6
- Learning rate: 0.08
- Subsample: 0.9
- Column sample: 0.9

---

##  URL Features

PhishGuard extracts **22 features** directly from the submitted URL.

Examples include:

- URL length
- Domain length
- IP address detection
- Number of subdomains
- Letter ratio
- Digit count
- Digit ratio
- Special-character count
- Special-character ratio
- HTTPS presence
- Path length
- Query length
- Path depth
- Hyphen count
- Dot count
- `@` count
- `%` count
- Character entropy
- Suspicious-token count

Suspicious tokens considered by the feature extractor include terms such as:

`login`, `signin`, `verify`, `account`, `update`, `secure`, `password`, `billing`, `support`, `confirm`, `wallet`, and `bank`.

---

## 📊 Dataset

The models were trained using the **PhiUSIIL Phishing URL (Website) Dataset** from the UCI Machine Learning Repository.

### Dataset Information

- Total instances: **235,795**
- Legitimate URLs: **134,850**
- Phishing URLs: **100,945**
- Train/Test Split: **80/20**
- Split Type: **Stratified**
- Random State: **42**

For model training, phishing is treated as the positive class.

---

##  Model Performance

| Metric | Random Forest | XGBoost |
|---|---:|---:|
| Accuracy | 99.52% | 99.57% |
| Precision | 99.71% | 99.84% |
| Recall | 99.18% | 99.16% |
| F1-Score | 99.44% | 99.50% |
| ROC-AUC | 99.70% | 99.78% |
| Mean Model Inference | 87.34 ms | 10.58 ms |

These results are from the held-out test partition of the dataset and should not be interpreted as guaranteed performance on every real-world URL.

---

## Risk Scoring

The model probability is converted into a risk score:

Risk Score = Round(Phishing Probability × 100)

### Risk Levels

| Score | Classification |
|---|---|
| 0–34 | 🟢 Low Risk |
| 35–69 | 🟡 Suspicious |
| 70–100 | 🔴 High Risk |

The score represents the model's estimated phishing probability. It is not proof that a website is safe or malicious.

---

##  Technology Stack

### Machine Learning
- Python
- Scikit-learn
- XGBoost
- Pandas
- Joblib

### Backend
- Flask

### Frontend
- HTML
- CSS
- JavaScript

### Dataset
- UCI Machine Learning Repository – PhiUSIIL

---

##  Project Structure

    PhishGuard/
    │
    ├── app.py
    │
    ├── src/
    │   ├── features.py
    │   └── train.py
    │
    ├── models/
    │   ├── random_forest.joblib
    │   └── xgboost.joblib
    │
    ├── templates/
    │   └── index.html
    │
    ├── static/
    │   ├── style.css
    │   └── app.js
    │
    ├── reports/
    │
    ├── requirements.txt
    └── README.md

---

##  Running the Project

### 1. Clone the repository

    git clone <your-repository-url>

### 2. Enter the project directory

    cd PhishGuard

### 3. Create a virtual environment

Windows:

    python -m venv .venv
    .venv\Scripts\activate

macOS/Linux:

    python3 -m venv .venv
    source .venv/bin/activate

### 4. Install dependencies

    pip install -r requirements.txt

### 5. Train the models

    python -m src.train

### 6. Start the Flask application

    python app.py

### 7. Open the application

Open the local Flask address displayed in the terminal, normally:

    http://127.0.0.1:5000

---

##  Example Workflow

If a user enters a previously unseen URL, PhishGuard does not need to find that exact URL in the training dataset.

Instead:

    New URL
       ↓
    Extract 22 Features
       ↓
    Random Forest + XGBoost
       ↓
    Calibrated Phishing Probability
       ↓
    Risk Score
       ↓
    Low / Suspicious / High Risk

This allows the trained models to evaluate URLs that were not explicitly present in the training data.

---

##  Limitations

PhishGuard is a research prototype and should not be treated as a complete replacement for professional cybersecurity systems.

The current system uses a hybrid URL-string pipeline: character TF-IDF plus 22 locally computed structural features. The same extractor and preprocessing artifacts are used in training and serving to prevent train/serve feature mismatch. No trusted-domain whitelist is used. A sophisticated phishing website may use a normal-looking URL, while some legitimate URLs may contain unusual patterns and receive a higher risk score.

Future validation should include independent datasets, domain-grouped testing, chronological testing and additional security signals.

---

## Future Scope

Future improvements may include:

- Browser extension integration
- Email link scanning
- REST API deployment
- DNS and domain reputation analysis
- SSL/TLS certificate information
- Domain-age analysis
- Independent real-world dataset testing
- Domain-grouped validation
- Chronological phishing detection experiments
- Improved explainability for risk scores

---

##  Authors

**Ashwin BG**  
**Alagarraj K**  
**Ajaay RS**  
**Dheeraj Reddy**

### Mentor
**Ms. C. Kudiyarasudevi**

Department of Computer Science and Engineering  
SRM Institute of Science and Technology  
Chennai, Tamil Nadu, India

---

##  Project Title

**Real-Time Phishing URL Detection Risk Scoring using Random Forest and XGBoost**

---

##  Disclaimer

PhishGuard is developed for academic and cybersecurity research purposes. Predictions are generated by machine-learning models and may contain false positives or false negatives. Users should not rely on the risk score as the sole basis for deciding whether a website is safe.
