"""
Test suite for util.py
Tests certificate and signature verification utilities
Tests generated with the help of Warp Terminal AI upon my instructions.
"""

import pytest
import tempfile
import os
from rekor_log_verifier.util import extract_public_key, verify_artifact_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


class TestExtractPublicKey:
    """Test cases for extract_public_key"""
    
    def test_extract_public_key_valid_cert(self):
        """Test extracting public key from a valid certificate"""
        # Generate a self-signed certificate for testing
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test@example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=1)
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        result = extract_public_key(cert_pem)
        assert isinstance(result, bytes)
        assert b"BEGIN PUBLIC KEY" in result


class TestVerifyArtifactSignature:
    """Test cases for verify_artifact_signature"""
    
    def test_verify_artifact_signature_invalid(self):
        """Test verify artifact signature with invalid signature"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test content")
            temp_file = f.name
        
        try:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            invalid_signature = b"invalid signature bytes"
            result = verify_artifact_signature(invalid_signature, public_key_pem, temp_file)
            assert result is False
        finally:
            os.unlink(temp_file)
    
    def test_verify_artifact_signature_valid(self):
        """Test verify artifact signature with valid signature"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            data = b"test content"
            f.write(data)
            temp_file = f.name
        
        try:
            # Create a valid signature
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Sign the data
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            
            result = verify_artifact_signature(signature, public_key_pem, temp_file)
            assert result is True
        finally:
            os.unlink(temp_file)
