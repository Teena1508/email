import numpy as np
from typing import Dict, Any, List, Union
from app.tls_analysis.models import CryptoAssessment, SeverityLevel

FEATURE_NAMES = [
    "tls_version_ordinal",
    "cipher_strength_score",
    "has_forward_secrecy",
    "cert_validity_days",
    "key_length_bits",
    "sig_algo_strength",
    "ja3_rarity_score",
    "starttls_anomaly_flag",
    "finding_count_critical_high",
    "finding_count_medium"
]

class FeatureExtractor:
    """
    Engineers a 10-dimensional numerical feature vector from a CryptoAssessment object
    or a synthetic JSON label dictionary.
    """

    @staticmethod
    def extract_from_assessment(assessment: CryptoAssessment) -> np.ndarray:
        # 1. TLS Version Ordinal
        tls_ver = assessment.tls_version_negotiated
        if tls_ver == "TLS 1.3":
            tls_ord = 4.0
        elif tls_ver == "TLS 1.2":
            tls_ord = 3.0
        elif tls_ver == "TLS 1.1":
            tls_ord = 2.0
        elif tls_ver == "TLS 1.0":
            tls_ord = 1.0
        elif tls_ver in ["SSL 3.0", "SSL 2.0"]:
            tls_ord = 0.0
        else:
            tls_ord = -1.0

        # 2. Cipher Strength Score
        cipher = (assessment.cipher_suite or "").upper()
        if "AES_256_GCM" in cipher or "CHACHA20" in cipher:
            cipher_score = 100.0
        elif "AES_128_GCM" in cipher:
            cipher_score = 90.0
        elif "AES_256_CBC" in cipher:
            cipher_score = 70.0
        elif "AES_128_CBC" in cipher:
            cipher_score = 60.0
        elif "3DES" in cipher:
            cipher_score = 20.0
        elif "RC4" in cipher or "EXPORT" in cipher or "NULL" in cipher:
            cipher_score = 0.0
        else:
            cipher_score = -1.0 if assessment.encryption_type == "NONE" else 50.0

        # 3. Has Forward Secrecy
        fs_flag = 1.0 if assessment.is_forward_secrecy else 0.0

        # 4. Cert Validity Days & Key Length & Sig Algo
        cert = assessment.cert_details
        if cert:
            cert_days = float(cert.days_until_expiration) if cert.days_until_expiration is not None else 365.0
            if cert.is_expired:
                cert_days = -30.0
            key_len = float(cert.key_size_bits)
            sig_algo = (cert.signature_algo or "").lower()
            if "sha256" in sig_algo or "sha384" in sig_algo or "sha512" in sig_algo:
                sig_score = 100.0
            elif "sha1" in sig_algo:
                sig_score = 20.0
            else:
                sig_score = 50.0
        else:
            cert_days = 0.0
            key_len = 0.0
            sig_score = 0.0

        # 5. JA3 Rarity Score
        ja3 = assessment.ja3
        if ja3 and ja3.matched_known_bad:
            ja3_score = 100.0
        elif ja3 and ja3.ja3_string:
            ja3_score = 0.0
        else:
            ja3_score = 0.0

        # 6. STARTTLS Anomaly Flag
        starttls_anomaly = 1.0 if assessment.encryption_type == "NONE" else 0.0

        # 7. Finding Counts
        crit_high_count = float(sum(1 for f in assessment.findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]))
        med_count = float(sum(1 for f in assessment.findings if f.severity == SeverityLevel.MEDIUM))

        features = [
            tls_ord,
            cipher_score,
            fs_flag,
            cert_days,
            key_len,
            sig_score,
            ja3_score,
            starttls_anomaly,
            crit_high_count,
            med_count
        ]
        return np.array(features, dtype=np.float64)

    @staticmethod
    def extract_from_label_dict(label: Dict[str, Any]) -> np.ndarray:
        gt = label.get("ground_truth", {})
        attack_type = label.get("attack_type", "clean_baseline")

        tls_ver = gt.get("tls_version")
        if tls_ver == "TLS 1.3":
            tls_ord = 4.0
        elif tls_ver == "TLS 1.2":
            tls_ord = 3.0
        elif tls_ver == "TLS 1.1":
            tls_ord = 2.0
        elif tls_ver == "TLS 1.0":
            tls_ord = 1.0
        else:
            tls_ord = -1.0

        cipher = (gt.get("cipher_suite") or "").upper()
        if "AES_128_GCM" in cipher or "AES_256_GCM" in cipher:
            cipher_score = 90.0
        elif "AES_128_CBC" in cipher or "AES_256_CBC" in cipher:
            cipher_score = 60.0
        elif "3DES" in cipher:
            cipher_score = 20.0
        elif "RC4" in cipher:
            cipher_score = 0.0
        else:
            cipher_score = -1.0 if attack_type == "starttls_stripping" else 50.0

        fs_flag = 1.0 if gt.get("forward_secrecy", False) else 0.0

        cert_st = gt.get("cert_status", "valid")
        if cert_st == "expired":
            cert_days = -30.0
        elif cert_st == "valid":
            cert_days = 365.0
        else:
            cert_days = 0.0

        key_len = 2048.0 if cert_st == "valid" else (1024.0 if cert_st == "self_signed" else 0.0)
        sig_score = 100.0 if cert_st == "valid" else (20.0 if cert_st == "expired" else 0.0)

        ja3_score = 70.0 if gt.get("ja3_anomaly", False) else 0.0
        if attack_type == "anomalous_ja3":
            ja3_score = 70.0

        starttls_anomaly = 1.0 if attack_type == "starttls_stripping" or gt.get("starttls_status") != "negotiated" else 0.0

        crit_high_count = 0.0
        med_count = 0.0
        if attack_type in ["starttls_stripping"]:
            crit_high_count = 2.0
        elif attack_type in ["downgrade_attack", "weak_cipher", "expired_cert"]:
            crit_high_count = 1.0
        elif attack_type in ["self_signed_cert", "no_forward_secrecy"]:
            med_count = 1.0

        features = [
            tls_ord,
            cipher_score,
            fs_flag,
            cert_days,
            key_len,
            sig_score,
            ja3_score,
            starttls_anomaly,
            crit_high_count,
            med_count
        ]
        return np.array(features, dtype=np.float64)
