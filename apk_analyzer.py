import os
import re
import hashlib
from collections import defaultdict
from androguard.core.bytecodes.apk import APK

class APKAnalyzer:
    def __init__(self):
        self.banking_keywords = [
            'bank', 'banking', 'credit', 'debit', 'transaction', 'payment',
            'upi', 'wallet', 'paytm', 'phonepe', 'gpay', 'bhim', 'sbi',
            'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'canara', 'boi'
        ]
        self.suspicious_permissions = [
            'android.permission.SEND_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.RECEIVE_BOOT_COMPLETED',
            'android.permission.DEVICE_ADMIN'
        ]

    def analyze_apk(self, apk_path):
        try:
            apk = APK(apk_path)
            results = {
                'basic_info': self.extract_basic_info_fixed(apk, apk_path),
                'permissions': self.extract_permissions_fixed(apk),
                'activities': self.extract_activities_fixed(apk),
                'services': self.extract_services_fixed(apk),
                'receivers': self.extract_receivers_fixed(apk),
                'suspicious_strings': self.find_suspicious_strings_fixed(apk),
                'certificate_info': self.analyze_certificate_fixed(apk),
                'network_analysis': self.analyze_network_behavior_fixed(apk),
                'file_analysis': self.analyze_file_structure_fixed(apk),
                'banking_indicators': self.check_banking_indicators(apk)
            }
            return results
        except Exception as e:
            return {'error': f'APK analysis failed: {str(e)}'}

    def extract_basic_info_fixed(self, apk, apk_path):
        try:
            return {
                'package_name': apk.get_package(),
                'app_name': apk.get_app_name(),
                'version_name': apk.get_androidversion_name(),
                'version_code': apk.get_androidversion_code(),
                'min_sdk': apk.get_min_sdk_version(),
                'target_sdk': apk.get_target_sdk_version(),
                'file_size': os.path.getsize(apk_path),
                'file_hash': self.calculate_hash(apk_path)
            }
        except Exception as e:
            return {'error': f'Failed to extract basic info: {str(e)}'}
        
    def extract_permissions_fixed(self, apk):
        try:
            permissions = apk.get_permissions()
            suspicious_perms = [p for p in permissions if p in self.suspicious_permissions]
            return {
                'all_permissions': list(permissions),
                'suspicious_permissions': suspicious_perms,
                'suspicious_count': len(suspicious_perms),
                'total_count': len(permissions)
            }
        except Exception as e:
            return {'error': f'Failed to extract permissions: {str(e)}'}

    def extract_activities_fixed(self, apk):
        try:
            return list(apk.get_activities())[:20]
        except:
            return []
    def extract_services_fixed(self, apk):
        try:
            return list(apk.get_services())[:20]
        except:
            return []
    def extract_receivers_fixed(self, apk):
        try:
            return list(apk.get_receivers())[:20]
        except:
            return []
    def check_banking_indicators(self, apk):
        indicators = {
            'has_banking_keywords': False,
            'suspicious_package_name': False,
            'potential_fake_bank': False,
            'banking_keywords_found': []
        }
        try:
            package_name = apk.get_package().lower()
            app_name = apk.get_app_name().lower()
            for keyword in self.banking_keywords:
                if keyword in package_name or keyword in app_name:
                    indicators['has_banking_keywords'] = True
                    indicators['banking_keywords_found'].append(keyword)
            suspicious_patterns = [
                'com.android.', 'com.google.', 'com.samsung.',
                'system.', 'android.', 'bank.official'
            ]
            for pattern in suspicious_patterns:
                if pattern in package_name and indicators['has_banking_keywords']:
                    indicators['suspicious_package_name'] = True
            indicators['potential_fake_bank'] = (
                indicators['has_banking_keywords'] and
                (indicators['suspicious_package_name'] or len(indicators['banking_keywords_found']) > 2)
            )
        except Exception as e:
            indicators['error'] = str(e)
        return indicators

    def find_suspicious_strings_fixed(self, apk):
        suspicious_patterns = [
            r'(?i)(password|pin|otp|cvv|card.*number)',
            r'(?i)(bank.*details|account.*number|ifsc)',
            r'(?i)(phishing|keylog|steal|hack)',
            r'(?i)(sms.*intercept|call.*forward)',
            r'https?://(?!.*(?:google|facebook|twitter))[^\s]+',
            r'(?i)(root|superuser|busybox)',
            r'(?i)(encrypt.*data|decrypt.*data)',
            r'(?i)(send.*sms|read.*sms)'
        ]
        found_patterns = defaultdict(list)
        try:
            files = apk.get_files()
            for filename in files[:50]:
                if filename.endswith(('.xml', '.txt', '.json')):
                    try:
                        content = str(apk.get_file(filename))
                        for pattern in suspicious_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                found_patterns[filename].extend(matches[:5])
                    except:
                        continue
        except Exception as e:
            found_patterns['error'] = str(e)
        return dict(found_patterns)

    def analyze_certificate_fixed(self, apk):
        try:
            certificates = apk.get_certificates()
            cert_info = {
                'has_certificate': bool(certificates),
                'cert_count': len(certificates),
                'certificates': []
            }
            for cert in certificates:
                cert_details = {
                    'subject': str(cert.subject),
                    'issuer': str(cert.issuer),
                    'serial_number': str(cert.serial_number)
                }
                cert_info['certificates'].append(cert_details)
            return cert_info
        except Exception as e:
            return {'error': f'Certificate analysis failed: {str(e)}'}

    def analyze_network_behavior_fixed(self, apk):
        network_indicators = {
            'urls': [],
            'ip_addresses': [],
            'suspicious_domains': []
        }
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        try:
            files = apk.get_files()
            for filename in files[:20]:
                if filename.endswith(('.xml', '.txt', '.json')):
                    try:
                        content = str(apk.get_file(filename))
                        urls = re.findall(url_pattern, content)[:5]
                        network_indicators['urls'].extend(urls)
                        ips = re.findall(ip_pattern, content)[:5]
                        network_indicators['ip_addresses'].extend(ips)
                    except:
                        continue
        except Exception as e:
            network_indicators['error'] = str(e)
        return network_indicators

    def analyze_file_structure_fixed(self, apk):
        structure_info = {
            'total_files': 0,
            'dex_files': 0,
            'native_libs': 0,
            'resources': 0,
            'unusual_files': []
        }
        try:
            files = apk.get_files()
            structure_info['total_files'] = len(files)
            for filename in files:
                if filename.endswith('.dex'):
                    structure_info['dex_files'] += 1
                elif filename.startswith('lib/'):
                    structure_info['native_libs'] += 1
                elif filename.startswith('res/'):
                    structure_info['resources'] += 1
                elif not any(filename.startswith(prefix) for prefix in
                             ['META-INF/', 'res/', 'lib/', 'classes', 'AndroidManifest']):
                    structure_info['unusual_files'].append(filename)
        except Exception as e:
            structure_info['error'] = str(e)
        return structure_info

    def calculate_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def extract_ml_features(self, analysis_results):
        features = []
        basic_info = analysis_results.get('basic_info', {})
        features.append(basic_info.get('file_size', 0) / 1024 / 1024)  # MB
        permissions = analysis_results.get('permissions', {})
        features.append(permissions.get('suspicious_count', 0))
        features.append(permissions.get('total_count', 0))
        banking = analysis_results.get('banking_indicators', {})
        features.append(1 if banking.get('has_banking_keywords', False) else 0)
        features.append(1 if banking.get('suspicious_package_name', False) else 0)
        features.append(len(banking.get('banking_keywords_found', [])))
        network = analysis_results.get('network_analysis', {})
        features.append(len(network.get('urls', [])))
        features.append(len(network.get('ip_addresses', [])))
        structure = analysis_results.get('file_analysis', {})
        features.append(structure.get('dex_files', 0))
        features.append(len(structure.get('unusual_files', [])))
        cert_info = analysis_results.get('certificate_info', {})
        features.append(1 if cert_info.get('has_certificate', False) else 0)
        suspicious_strings = analysis_results.get('suspicious_strings', {})
        features.append(len(suspicious_strings))
        return features

