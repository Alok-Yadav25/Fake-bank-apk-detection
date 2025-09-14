import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib

class MLDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'file_size_mb', 'suspicious_permissions', 'total_permissions',
            'has_banking_keywords', 'suspicious_package_name', 'banking_keywords_count',
            'url_count', 'ip_count', 'dex_files_count', 'unusual_files_count',
            'has_certificate', 'suspicious_strings_count'
        ]
        self.load_model()
        if not self.is_trained:
            self.train_default_model()

    def train_default_model(self):
        print("Training default model with synthetic data...")
        X_train, y_train = self.generate_better_synthetic_data()
        self.train_model(X_train, y_train)
        self.save_model()

    def generate_better_synthetic_data(self, n_samples=1000):
        np.random.seed(42)
        X = np.random.randn(n_samples, len(self.feature_names))
        y = np.random.randint(0, 2, n_samples)
        for i in range(n_samples):
            if y[i] == 1:
                X[i, 1] += np.random.uniform(3, 8)
                X[i, 3] = np.random.choice([0, 1], p=[0.3, 0.7])
                X[i, 4] = np.random.choice([0, 1], p=[0.4, 0.6])
                X[i, 9] += np.random.uniform(2, 6) 
                X[i, 10] = np.random.choice([0, 1], p=[0.6, 0.4])
                X[i, 11] += np.random.uniform(4, 10)
            else:
                X[i, 1] = max(0, X[i, 1])
                X[i, 10] = np.random.choice([0, 1], p=[0.2, 0.8])
        return X, y

    def train_model(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        self.model.fit(X_train_scaled, y_train)
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model trained with accuracy: {accuracy:.2f}")
        self.is_trained = True

    def predict(self, features):
        if not self.is_trained:
            return {'is_malicious': False, 'confidence': 0.0, 'error': 'Model not trained'}
        try:
            if len(features) != len(self.feature_names):
                features = features[:len(self.feature_names)]
                while len(features) < len(self.feature_names):
                    features.append(0)
            features_array = np.array(features).reshape(1, -1)
            features_scaled = self.scaler.transform(features_array)
            prediction = self.model.predict(features_scaled)[0]
            prediction_proba = self.model.predict_proba(features_scaled)[0]
            confidence = max(prediction_proba)
            feature_importance = self.model.feature_importances_
            suspicious_features = self.get_suspicious_features(features, feature_importance)
            return {
                'is_malicious': bool(prediction),
                'confidence': float(confidence),
                'probability_malicious': float(prediction_proba[1]),
                'probability_benign': float(prediction_proba[0]),
                'suspicious_features': suspicious_features
            }
        except Exception as e:
            return {'is_malicious': False, 'confidence': 0.0, 'error': f'Prediction failed: {str(e)}'}

    def get_suspicious_features(self, features, feature_importance, threshold=0.1):
        suspicious = []
        for i, (feature_name, value, importance) in enumerate(zip(self.feature_names, features, feature_importance)):
            if importance > threshold and value > 0:
                suspicious.append({
                    'feature': feature_name,
                    'value': value,
                    'importance': importance,
                    'description': self.get_feature_description(feature_name, value)
                })
        return sorted(suspicious, key=lambda x: x['importance'], reverse=True)[:5]

    def get_feature_description(self, feature_name, value):
        descriptions = {
            'suspicious_permissions': f"App requests {int(value)} suspicious permissions",
            'suspicious_strings_count': f"Found {int(value)} suspicious text patterns",
            'url_count': f"Contains {int(value)} external URLs",
            'ip_count': f"Contains {int(value)} IP addresses",
            'unusual_files_count': f"Has {int(value)} unusual files",
            'file_size': f"File size is {value:.1f} MB",
            'dex_files_count': f"Contains {int(value)} executable files"
        }
        return descriptions.get(feature_name, f"{feature_name}: {value}")

    def save_model(self):
        if self.model and self.is_trained:
            os.makedirs('models', exist_ok=True)
            joblib.dump(self.model, 'models/banking_apk_detector.pkl')
            joblib.dump(self.scaler, 'models/feature_scaler.pkl')
            print("Model saved successfully")

    def load_model(self):
        try:
            if os.path.exists('models/banking_apk_detector.pkl'):
                self.model = joblib.load('models/banking_apk_detector.pkl')
                self.scaler = joblib.load('models/feature_scaler.pkl')
                self.is_trained = True
                print("Pre-trained model loaded successfully")
                return True
        except Exception as e:
            print(f"Failed to load model: {e}")
        return False

    def retrain_with_new_data(self, new_features, new_labels):
        if len(new_features) != len(new_labels):
            raise ValueError("Features and labels must have same length")
        X_new = np.array(new_features)
        y_new = np.array(new_labels)
        self.train_model(X_new, y_new)
        self.save_model()
        return True
