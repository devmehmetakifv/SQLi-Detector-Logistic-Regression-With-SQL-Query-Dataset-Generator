# SQL Injection Detection System

A comprehensive machine learning-based SQL Injection (SQLi) detection system featuring a sophisticated synthetic query generator, multi-generation model training, and robust evaluation framework.

## 🎯 Project Overview

This project implements an end-to-end pipeline for detecting SQL injection attacks using machine learning. The system generates synthetic training data, trains classification models, and provides tools for comprehensive model evaluation and comparison.

### Key Features

- **Synthetic Query Generator**: Produces millions of diverse benign and malicious SQL queries
- **Multi-Context Attack Generation**: Generates payloads as standalone, fragments, URL-encoded, and injected in queries
- **Automated Dataset Splitting**: 80/10/10 train/test/validation splits with unique random seeds
- **Multi-Generation Training**: Track model evolution across training iterations
- **Comprehensive Evaluation**: Category-level analysis, confusion matrices, and false positive/negative tracking

## 📊 Model Performance

### Generation Comparison (Evaluated on external dataset)

| Metric | Gen 1 | Gen 2 | Gen 3 | Gen 4 |
|--------|-------|-------|-------|-------|
| **Accuracy** | 38.99% | 52.80% | 63.29% | 67.04% |
| **Precision** | 37.63% | 43.82% | 50.07% | 60.27% |
| **Recall** | 99.96% | 99.98% | 99.97% | 30.67% |
| **F1 Score** | 54.67% | 60.93% | 66.73% | 40.65% |
| **ROC-AUC** | 0.528 | 0.897 | 0.938 | 0.716 |

### Analysis

- **Gen 1-3**: High recall (99.9%+) but lower precision. Models flag almost everything as malicious.
- **Gen 4**: Higher precision (60.27%) with attack signature-focused training. Lower recall due to stricter attack pattern recognition.

> **Note**: Gen 4 was trained with enhanced attack signature detection, which improves precision but reduces recall on edge cases (single keywords, unusual patterns).

## 🗂️ Project Structure

```
sql_query_generator/
├── sql_query_generator/
│   └── sql_query_generator.py    # Core synthetic query generator
├── dataset/
│   ├── train/
│   │   ├── benign.txt            # 80% training benign queries
│   │   └── malicious.txt         # 80% training malicious queries
│   ├── test/
│   │   ├── benign.txt            # 10% test benign queries
│   │   └── malicious.txt         # 10% test malicious queries
│   └── val/
│       ├── benign.txt            # 10% validation benign queries
│       └── malicious.txt         # 10% validation malicious queries
├── generations/                   # Trained model generations
├── evaluations/                   # Evaluation results and comparisons
├── train_sqli_detector.ipynb     # Model training notebook
└── evaluate_models.ipynb          # Multi-generation evaluation notebook
```

## 🚀 Quick Start

### Prerequisites

```bash
pip install scikit-learn pandas numpy matplotlib seaborn joblib
```

### Generate Training Data

```bash
# Generate 200,000 queries per class (400K total)
python sql_query_generator/sql_query_generator.py 200000
```

Creates:
- **Train**: 160,000 benign + 160,000 malicious
- **Test**: 20,000 benign + 20,000 malicious
- **Val**: 20,000 benign + 20,000 malicious

### Train a Model

Run `train_sqli_detector.ipynb` to train and save a model.

### Evaluate Models

Run `evaluate_models.ipynb` to compare generations.

## 🔧 Query Generator Architecture

### Benign Query Distribution (Gen 4)

| Type | Percentage | Description |
|------|------------|-------------|
| Standard SQL | 60% | SELECT, INSERT, UPDATE queries |
| Hard Negatives | 20% | Legitimate UNION, OR, comments |
| Benign Noise | 10% | Keywords, text, emails, JSON |
| SQL Variety | 10% | Additional patterns |

### Malicious Query Distribution (Gen 4)

| Context | Percentage | Example |
|---------|------------|---------|
| Full query injection | 50% | `SELECT * FROM users WHERE id='1' OR 1=1--'` |
| Standalone payload | 20% | `' UNION SELECT 1,2,3--` |
| Fragment | 15% | `admin' OR 1=1--` |
| URL-encoded | 15% | `%27%20OR%201=1--` |

### Attack Payload Categories

- **Tautologies** (20%): `OR 1=1`, `OR 'a'='a'`
- **UNION-based** (15%): Data exfiltration
- **Comment injection** (10%): `--`, `#`, `/**/`
- **Boolean Blind** (10%): True/false inference
- **Time-based Blind** (8%): SLEEP/BENCHMARK
- **Error-based** (7%): Error message extraction
- **Stacked Queries** (5%): Multiple statements
- **Obfuscated** (25%): Mixed case, whitespace, encoding

## 📈 Training Details

### Feature Extraction

- **TF-IDF Vectorization**: 15,000 character n-grams
- **N-gram Range**: (2, 5)
- **Sublinear TF**: Enabled

### Model

- **Algorithm**: Logistic Regression
- **Regularization**: L2
- **Class Weights**: Balanced

## 🎯 Precision vs Recall Tradeoff

The evaluation dataset contains patterns that represent a spectrum of "maliciousness":

| Pattern Type | Gen 1-3 | Gen 4 |
|--------------|---------|-------|
| Clear attacks (`OR 1=1--`) | ✅ Detected | ✅ Detected |
| Single keywords (`insert`, `select`) | ✅ Flagged | ❌ Ignored (benign) |
| Unusual patterns (`or 3=3`) | ✅ Flagged | ❌ Ignored |

**Choose based on use case:**
- **High Recall (Gen 1-3)**: WAF blocking all suspicious input
- **High Precision (Gen 4)**: Reduce false positives on legitimate queries

## 📝 API Reference

### CLI Usage

```bash
# Generate dataset with splits
python sql_query_generator.py 200000

# Generate specific types
python sql_query_generator.py --benign -n 50000 -o benign.txt
python sql_query_generator.py --malicious -n 50000 -o malicious.txt
```

### Programmatic Usage

```python
from sql_query_generator import generate_queries, generate_one_benign, generate_one_malicious

benign = generate_queries("benign", 1000)
malicious = generate_queries("malicious", 1000)
```

## 📄 License

Educational and research purposes.

## 🙏 Acknowledgments

- Built with scikit-learn, pandas, matplotlib
- SQLi patterns inspired by OWASP
- Developed through iterative improvement
