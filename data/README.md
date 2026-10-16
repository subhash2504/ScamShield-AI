# PhishGuard AI Dataset Documentation & Provenance

## 1. Overview
The PhishGuard AI dataset repository contains curated, documented text and URL samples used for training and evaluating machine learning classification models for phishing, scam, and legitimate communications.

## 2. Dataset Provenance & Sources
The training corpus incorporates samples representative of public phishing research benchmarks and security feeds:
1. **SMS / Spam Research Collection** (derived from public SMS Spam Collection benchmarks, University of California Irvine / Tiago A. Almeida & José María Gómez Hidalgo, CC BY 4.0).
2. **Email Phishing Benchmarks** (derived from open security corpora such as Nazario phishing corpus & Enron legitimate communication corpus).
3. **URL Threat Feeds & Benchmarks** (curated benign web domains vs. phishing patterns derived from OpenPhish & PhishTank feed indicators).

## 3. License & Responsible Use
- **License**: Creative Commons Attribution 4.0 International (CC BY 4.0).
- **Responsible Use**: Samples are strictly sanitized. No real passwords, live active credentials, or identifiable personal victim data (PII) are stored. Any simulated malicious links point to test/neutral domains or defanged patterns (e.g. `example.com`, `hxxp://`).

## 4. Label Definitions
- **`0` (Legitimate / Benign)**:
  Authentic transactional notifications, routine personal messages, standard email newsletters, and verified domain structures that exhibit normal linguistic and technical characteristics without deception or urgency coercion.
- **`1` (Phishing / Scam / Malicious)**:
  Communications or URLs employing social engineering tactics, artificial urgency, impersonation of financial/governmental institutions, deceptive credential harvesting links, lottery/prize scams, or obfuscated URL constructs designed to mislead recipients.

## 5. Dataset Structure
Data is formatted in JSON / CSV schemas containing:
- `id`: Unique sample identifier
- `text`: Message or email content
- `label`: Binary classification (0 = Benign, 1 = Phishing)
- `type`: Category (`sms`, `email`, `whatsapp`, `url`)
- `source`: Dataset subset source

## 6. Preprocessing & Leakage Prevention
- **Deduplication**: Exact and near-duplicate text samples are stripped before splitting.
- **Stratified Partitioning**: The dataset is split into Training (70%), Validation (15%), and Test (15%) with balanced label proportions across splits.
- **Feature Isolation**: Vectorizer vocabularies and scaling parameters are fitted exclusively on the training split to eliminate data leakage into test metrics.

## 7. Limitations
- Attackers continuously alter linguistic styles and zero-day domain generation algorithms.
- Purely synthetic or small datasets cannot capture all adversarial variations; the system pairs ML classifiers with explainable heuristic security rules.
