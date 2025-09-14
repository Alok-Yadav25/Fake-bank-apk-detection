# Fake-bank-apk-detection

Detect fake / phishing bank APKs using static analysis + ML
This project combines Android static-analysis (Androguard), Python utilities (e.g., hashlib), machine learning (scikit-learn / LightGBM / similar), and a simple web UI (HTML, CSS, JS) + Python backend to detect potentially fraudulent bank APKs.

1. Project overview

The system analyzes uploaded APK files (static analysis) to extract features useful for classification (permissions, API calls, strings, certificate info, hashes, resource anomalies). Extracted features feed an ML model that outputs a risk score (e.g., benign, suspicious, malicious). A lightweight web UI allows users to upload an APK and view results.


2. Features & approach

Common static features to extract:
	•	Package name, manifest permissions (suspicious banking/perms), exported activities/services.
	•	API calls / method usage patterns (e.g., reflection, dynamic code load).
	•	Strings: URLs, obfuscated class names, suspicious domain names.
	•	Certificates & signing info (certificate issuer, mismatch, self-signed).
	•	File-level metadata: size, number of dex methods, native libs.
	•	Hashes of APK and important files (MD5/SHA256) using hashlib.
	•	Resource anomalies: suspicious icons, overlays.
	•	Heuristics: known bad package names, mismatched resources vs. claimed bank.


3. Tech stack
	•	Static analysis: Androguard (Python) — parsing AndroidManifest, DEX analysis, disassembly.  ￼
	•	Hashing / checksums: hashlib (Python stdlib) for SHA256/MD5.  ￼
	•	ML: scikit-learn, XGBoost or LightGBM (training + inference).
	•	Backend server: Flask or FastAPI (Python).
	•	Frontend: HTML, CSS, JavaScript (vanilla or small framework).
	•	Data storage: SQLite / simple JSON for results; or a small DB for larger systems.
