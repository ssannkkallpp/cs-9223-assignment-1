"""
Test suite for merkle_proof.py
Tests Merkle tree operations and proof verification
"""

import pytest
import base64
from merkle_proof import (
    DefaultHasher, compute_leaf_hash, Hasher, RootMismatchError,
    verify_consistency, verify_inclusion, chain_inner, chain_inner_right,
    chain_border_right, root_from_inclusion_proof
)


class TestHasher:
    """Test cases for Hasher class"""
    
    def test_hasher_operations(self):
        """Test hasher hash_leaf and hash_children"""
        hasher = DefaultHasher
        leaf = b"test leaf data"
        leaf_hash = hasher.hash_leaf(leaf)
        assert len(leaf_hash) == 32
        
        left = b"left" * 8
        right = b"right" * 8
        children_hash = hasher.hash_children(left, right)
        assert len(children_hash) == 32
    
    def test_hasher_empty_root(self):
        """Test empty root generation"""
        hasher = DefaultHasher
        root = hasher.empty_root()
        assert len(root) == 32


class TestComputeLeafHash:
    """Test cases for compute_leaf_hash"""
    
    def test_compute_leaf_hash(self):
        """Test compute leaf hash from body"""
        body = base64.b64encode(b"test data").decode()
        result = compute_leaf_hash(body)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex string


class TestChainFunctions:
    """Test chain_inner, chain_inner_right, chain_border_right"""
    
    def test_chain_inner(self):
        """Test chain_inner hashing"""
        hasher = DefaultHasher
        seed = b"seed" * 8
        proof = [b"hash1" * 4, b"hash2" * 4]
        result = chain_inner(hasher, seed, proof, 0)
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_chain_inner_right(self):
        """Test chain_inner_right hashing"""
        hasher = DefaultHasher
        seed = b"seed" * 8
        proof = [b"hash1" * 4, b"hash2" * 4]
        result = chain_inner_right(hasher, seed, proof, 3)
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_chain_border_right(self):
        """Test chain_border_right hashing"""
        hasher = DefaultHasher
        seed = b"seed" * 8
        proof = [b"hash1" * 4, b"hash2" * 4]
        result = chain_border_right(hasher, seed, proof)
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestVerifyConsistency:
    """Test verify_consistency function"""
    
    def test_verify_consistency_same_size(self):
        """Test consistency with same tree sizes"""
        root = "a" * 64
        verify_consistency(DefaultHasher, 10, 10, [], root, root)
    
    def test_verify_consistency_size2_less_than_size1(self):
        """Test consistency fails when size2 < size1"""
        root = "a" * 64
        with pytest.raises(ValueError, match="size2.*< size1"):
            verify_consistency(DefaultHasher, 10, 5, [], root, root)
    
    def test_verify_consistency_size1_zero(self):
        """Test consistency with size1 = 0"""
        root = "a" * 64
        verify_consistency(DefaultHasher, 0, 10, [], root, root)
    
    def test_verify_consistency_with_proof(self):
        """Test consistency with non-empty proof"""
        # Create realistic roots and proof for tree sizes 1 and 2
        root1 = "a" * 64
        root2 = "b" * 64
        proof = ["c" * 64]
        
        with pytest.raises(RootMismatchError):
            verify_consistency(DefaultHasher, 1, 2, proof, root1, root2)


class TestRootMismatchError:
    """Test RootMismatchError"""
    
    def test_root_mismatch_error_str(self):
        """Test RootMismatchError string representation"""
        error = RootMismatchError(b"expected", b"calculated")
        error_str = str(error)
        assert "expected" in error_str.lower() or "calculated" in error_str.lower()


class TestRootFromInclusionProof:
    """Test root_from_inclusion_proof error cases"""
    
    def test_index_beyond_size(self):
        """Test that index >= size raises ValueError"""
        hasher = DefaultHasher
        leaf_hash = b"a" * 32
        with pytest.raises(ValueError, match="index is beyond size"):
            root_from_inclusion_proof(hasher, 10, 5, leaf_hash, [])
    
    def test_wrong_leaf_hash_size(self):
        """Test that wrong leaf hash size raises ValueError"""
        hasher = DefaultHasher
        leaf_hash = b"short"
        with pytest.raises(ValueError, match="leaf_hash has unexpected size"):
            root_from_inclusion_proof(hasher, 1, 10, leaf_hash, [])
