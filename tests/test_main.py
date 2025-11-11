"""
Test suite for main.py
Tests main Rekor verifier functions
Tests generated with the help of Warp Terminal AI upon my instructions.
"""

import pytest
import json
import tempfile
import os
from unittest.mock import patch, Mock
import requests
import base64

# Import functions to test
from main import get_log_entry, inclusion, get_latest_checkpoint, consistency, main


class TestGetLogEntry:
    """Test cases for get_log_entry function"""
    
    def test_get_log_entry_invalid_negative_index(self):
        """Test 1: Negative log index raises ValueError"""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            get_log_entry(-1, debug=False)
    
    def test_get_log_entry_invalid_string_index(self):
        """Test 2: String log index raises ValueError"""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            get_log_entry("invalid", debug=False)
    
    def test_get_log_entry_success(self):
        """Test 3: Successfully retrieve log entry"""
        mock_entry = Mock()
        mock_entry.body = base64.b64encode(b"test").decode()
        
        with patch('main.REKOR_CLIENT.log.entries.get', return_value=mock_entry):
            result = get_log_entry(12345, debug=True)
            assert result is not None


class TestInclusion:
    """Test cases for inclusion verification function"""
    
    def test_inclusion_invalid_log_index(self):
        """Test 4: Invalid log index raises ValueError"""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            inclusion(-5, "artifact.md", debug=False)
    
    def test_inclusion_missing_artifact_file(self):
        """Test 5: Non-existent artifact file raises ValueError"""
        with pytest.raises(ValueError, match="artifact file does not exist"):
            inclusion(123, "/nonexistent/path/file.txt", debug=False)
    
    def test_inclusion_artifact_is_directory(self):
        """Test 6: Directory instead of file raises ValueError"""
        with pytest.raises(ValueError, match="must be a file, not a directory"):
            inclusion(123, "/Users/sankalpramesh/cs-9223-assignment-1/tests", debug=False)
    
    def test_inclusion_empty_artifact_path(self):
        """Test 7: Empty artifact path raises ValueError"""
        with pytest.raises(ValueError, match="artifact_filepath cannot be empty"):
            inclusion(123, "", debug=False)
    
    def test_inclusion_no_signature_content(self):
        """Test 8: Inclusion with missing signature content"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test")
            temp_file = f.name
        
        try:
            mock_entry = Mock()
            body_data = {"spec": {"signature": {}}}
            mock_entry.body = base64.b64encode(json.dumps(body_data).encode()).decode()
            
            with patch('main.get_log_entry', return_value=mock_entry):
                result = inclusion(12345, temp_file, debug=True)
                assert result is False
        finally:
            os.unlink(temp_file)
    
    def test_inclusion_no_inclusion_proof(self):
        """Test 9: Inclusion with missing inclusion proof"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test")
            temp_file = f.name
        
        try:
            mock_entry = Mock()
            body_data = {
                "spec": {
                    "signature": {
                        "content": base64.b64encode(b"sig").decode(),
                        "publicKey": {"content": base64.b64encode(b"validcert").decode()}
                    }
                }
            }
            mock_entry.body = base64.b64encode(json.dumps(body_data).encode()).decode()
            mock_entry.inclusion_proof = None
            
            with patch('main.get_log_entry', return_value=mock_entry):
                with patch('main.extract_public_key', return_value=b"mock_public_key"):
                    with patch('main.verify_artifact_signature', return_value=True):
                        result = inclusion(12345, temp_file, debug=True)
                        assert result is False
        finally:
            os.unlink(temp_file)


class TestGetLatestCheckpoint:
    """Test cases for get_latest_checkpoint function"""
    
    def test_get_latest_checkpoint_success(self):
        """Test 10: Successfully retrieve checkpoint with required fields"""
        mock_checkpoint = {
            "treeID": "1193050959916656506",
            "treeSize": 483453541,
            "rootHash": "4a4ed18ea85a28a96b3d34ca48839927daf4de9cb7f7833b65e44730f1cf2684",
            "signedTreeHead": "mock_signed_tree_head"
        }
        
        mock_response = Mock()
        mock_response.json.return_value = mock_checkpoint
        
        with patch('main.REKOR_CLIENT.session.get', return_value=mock_response):
            result = get_latest_checkpoint(debug=False)
            assert result is not None
            assert 'treeID' in result
            assert 'treeSize' in result
            assert 'rootHash' in result
            assert result['treeSize'] > 0


class TestConsistency:
    """Test cases for consistency verification function"""
    
    def test_consistency_missing_tree_id(self):
        """Test 11: Previous checkpoint missing treeID returns False"""
        invalid_checkpoint = {
            "treeSize": 500,
            "rootHash": "abcd1234"
        }
        result = consistency(invalid_checkpoint, debug=False)
        assert result is False
    
    def test_consistency_empty_checkpoint(self):
        """Test 12: Empty previous checkpoint returns False"""
        result = consistency({}, debug=False)
        assert result is False
    
    def test_consistency_latest_checkpoint_none(self):
        """Test 13: Consistency when latest checkpoint is None"""
        valid_checkpoint = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "abc"
        }
        with patch('main.get_latest_checkpoint', return_value=None):
            result = consistency(valid_checkpoint, debug=True)
            assert result is False
    
    def test_consistency_verification_success(self):
        """Test 14: Successful consistency verification"""
        prev_checkpoint = {
            "treeID": "123",
            "treeSize": 50,
            "rootHash": "abc123" * 10 + "abcd"
        }
        latest_checkpoint = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "def456" * 10 + "defg"
        }
        mock_response = Mock()
        mock_response.json.return_value = {"hashes": []}
        
        with patch('main.get_latest_checkpoint', return_value=latest_checkpoint):
            with patch('main.REKOR_CLIENT.session.get', return_value=mock_response):
                with patch('main.verify_consistency'):
                    result = consistency(prev_checkpoint, debug=True)
                    assert result is True


class TestMainCLI:
    """Test cases for main() CLI function"""
    
    def test_main_checkpoint(self):
        """Test 15: main() with --checkpoint flag"""
        test_args = ['prog', '--checkpoint']
        mock_checkpoint = {"treeID": "123", "treeSize": 100, "rootHash": "abc"}
        
        with patch('sys.argv', test_args):
            with patch('main.get_latest_checkpoint', return_value=mock_checkpoint):
                main()
    
    def test_main_debug_checkpoint(self):
        """Test 16: main() with --debug and --checkpoint"""
        test_args = ['prog', '--debug', '--checkpoint']
        mock_checkpoint = {"treeID": "123", "treeSize": 100, "rootHash": "abc"}
        
        with patch('sys.argv', test_args):
            with patch('main.get_latest_checkpoint', return_value=mock_checkpoint):
                main()
    
    def test_main_inclusion(self):
        """Test 17: main() with --inclusion and --artifact"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = f.name
        
        try:
            test_args = ['prog', '--inclusion', '123', '--artifact', temp_file]
            
            with patch('sys.argv', test_args):
                with patch('main.inclusion', return_value=True):
                    main()
        finally:
            os.unlink(temp_file)
    
    def test_main_consistency_missing_tree_id(self):
        """Test 18: main() --consistency without tree-id"""
        test_args = ['prog', '--consistency']
        
        with patch('sys.argv', test_args):
            main()
    
    def test_main_consistency_missing_tree_size(self):
        """Test 19: main() --consistency without tree-size"""
        test_args = ['prog', '--consistency', '--tree-id', '123']
        
        with patch('sys.argv', test_args):
            main()
    
    def test_main_consistency_missing_root_hash(self):
        """Test 20: main() --consistency without root-hash"""
        test_args = ['prog', '--consistency', '--tree-id', '123', '--tree-size', '100']
        
        with patch('sys.argv', test_args):
            main()
    
    def test_main_consistency_complete(self):
        """Test 21: main() --consistency with all params"""
        test_args = ['prog', '--consistency', '--tree-id', '123', '--tree-size', '100', '--root-hash', 'abc']
        
        with patch('sys.argv', test_args):
            with patch('main.consistency', return_value=True):
                main()
