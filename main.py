import argparse
import json
import base64
import os
import warnings
from urllib.parse import urljoin

# Suppress urllib3 SSL warning for LibreSSL compatibility since I am running on mac
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL 1.1.1+")

from sigstore.sign import RekorClient
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    """
    Retrieve a log entry from the Rekor transparency log by index using sigstore-python.
    Added error handling with the help of cursor AI.

    Args:
        log_index (int): The index of the log entry to retrieve
        debug (bool): Enable debug output
        
    Returns:
        dict: JSON object of the log entry if found, None if not found
        
    Raises:
        ValueError: If log_index is not a valid non-negative integer
    """
    # Verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"log_index must be a non-negative integer, got: {log_index}")
    
    if debug:
        print(f"Retrieving log entry at index: {log_index}")
    
    try:
        # Create Rekor client using sigstore-python
        rekor_client = RekorClient("https://rekor.sigstore.dev/")
        if debug:
            print(f"Created Rekor client for production instance")
        # Get log entry by index using the correct method
        log_entry = rekor_client.log.entries.get(log_index=log_index)  
        return log_entry
            
    except Exception as e:
        if debug:
            print(f"Error occurred while fetching log entry {log_index}: {e}")
            print(f"Error type: {type(e).__name__}")
        return None

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    # This function is not used, hence I have chosen to not implement it
    pass

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # Implemented with help from cursor AI based on my instructions for input validation.
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"log_index must be a non-negative integer, got: {log_index}")
    
    if not artifact_filepath:
        raise ValueError("artifact_filepath cannot be empty or None")
    
    if not os.path.exists(artifact_filepath):
        raise ValueError(f"artifact file does not exist: {artifact_filepath}")
    
    if not os.path.isfile(artifact_filepath):
        raise ValueError(f"artifact_filepath must be a file, not a directory: {artifact_filepath}")
    
    if debug:
        print(f"Validated inputs - log_index: {log_index}, artifact_filepath: {artifact_filepath}")
    

    log_entry = get_log_entry(log_index, debug)
    leaf_hash = compute_leaf_hash(log_entry.body)
    body = base64.b64decode(log_entry.body)
    body_json = json.loads(body)
    
    # Extract signature and certificate content
    signature_content = body_json["spec"]["signature"]["content"]
    certificate_content = body_json["spec"]["signature"]["publicKey"]["content"]
    
    # Decode the Base64-encoded signature and certificate
    signature_bytes = base64.b64decode(signature_content)
    certificate_bytes = base64.b64decode(certificate_content)
    
    # Extract public key from certificate
    extracted_public_key = extract_public_key(certificate_bytes)
    # Verify artifact signature
    signature_verification = verify_artifact_signature(signature_bytes, extracted_public_key, artifact_filepath)
    if not signature_verification:
        if debug:
            print("Signature verification failed")
        return False

    # Extract verification data for inclusion proof
    inclusion_proof = log_entry.inclusion_proof
    if inclusion_proof:
        # Extract the required values
        index = inclusion_proof.log_index
        tree_size = inclusion_proof.tree_size
        root_hash = inclusion_proof.root_hash if inclusion_proof.root_hash else None
        hashes = inclusion_proof.hashes if inclusion_proof.hashes else []
        
        # Verify the merkle inclusion proof
        inclusion_result = verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
        # verify_inclusion returns None on success, raises exception on failure
        merkle_verification_success = inclusion_result is None
        
        if merkle_verification_success:
            print("Signature is valid.")
            print("Offline root hash calculation for inclusion is verified.")
        
        return merkle_verification_success
    else:
        if debug:
            print("No inclusion proof found in log entry")
        return False
            
def get_latest_checkpoint(debug=False):
    """
    Get the latest checkpoint from the Rekor transparency log.
    Generated with the help of Cursor AI based on my precise instructions and the /log endpoint
    
    Args:
        debug (bool): Enable debug output
        
    Returns:
        dict: Checkpoint data including tree ID, tree size, root hash
    """
    if debug:
        print("Retrieving latest checkpoint from Rekor server...")
    
    try:
        # Create Rekor client for session management
        rekor_client = RekorClient("https://rekor.sigstore.dev/")
        
        # Make direct HTTP request to get complete checkpoint data (including inactive shards)
        endpoint = urljoin(rekor_client.url, "log")
        response = rekor_client.session.get(endpoint)
        response.raise_for_status()
        
        # Get complete checkpoint data from response
        checkpoint = response.json()
        
        if debug:
            print(f"Retrieved checkpoint - Tree ID: {checkpoint['treeID']}")
            print(f"Tree Size: {checkpoint['treeSize']}")
            print(f"Root Hash: {checkpoint['rootHash']}")
            print(f"Signed Tree Head: {checkpoint['signedTreeHead']}")
            
            # Save to file if debug mode
            with open("checkpoint.json", "w") as f:
                json.dump(checkpoint, f, indent=4)
            print("Checkpoint saved to checkpoint.json")
        
        return checkpoint
        
    except Exception as e:
        if debug:
            print(f"Error retrieving checkpoint: {e}")
        raise

def consistency(prev_checkpoint, debug=False):
    """
    Verify consistency between a previous checkpoint and the latest checkpoint.
    Generated with cursor AI upon my instruction to do input validation
    Then check prev_checkpoint (input) details against latest checkpoint which is fetched with helper method
    
    Args:
        prev_checkpoint (dict): Previous checkpoint with treeID, treeSize, rootHash
        debug (bool): Enable debug output
        
    Returns:
        bool: True if consistency is verified, False otherwise
    """
    # Verify that prev checkpoint is not empty
    if not prev_checkpoint or not all(key in prev_checkpoint for key in ["treeID", "treeSize", "rootHash"]):
        if debug:
            print("Invalid previous checkpoint: missing required fields")
        return False
    
    if debug:
        print(f"Verifying consistency from tree size {prev_checkpoint['treeSize']} to latest...")
    
    try:
        # Get latest checkpoint
        latest_checkpoint = get_latest_checkpoint(debug)
        if not latest_checkpoint:
            if debug:
                print("Failed to retrieve latest checkpoint")
            return False
        
        # Check if tree has grown
        prev_size = prev_checkpoint['treeSize']
        latest_size = latest_checkpoint['treeSize']
        
        # Get consistency proof using sigstore client
        rekor_client = RekorClient("https://rekor.sigstore.dev/")
        proof_endpoint = "log/proof"
        params = {
            'firstSize': prev_size,
            'lastSize': latest_size,
            'treeID': prev_checkpoint['treeID']
        }
        
        if debug:
            print(f"Requesting consistency proof using sigstore client with params: {params}")
        
        endpoint = urljoin(rekor_client.url, proof_endpoint)
        response = rekor_client.session.get(endpoint, params=params)
        response.raise_for_status()
        
        proof_data = response.json()
        
        if debug:
            print(f"Received consistency proof with {len(proof_data.get('hashes', []))} hashes")
        
        # Verify consistency using merkle_proof module
        consistency_hashes = proof_data.get('hashes', [])
        
        # Use verify_consistency from merkle_proof.py
        try:
            verify_consistency(
                DefaultHasher,
                prev_size,
                latest_size,
                consistency_hashes,
                prev_checkpoint['rootHash'],
                latest_checkpoint['rootHash']
            )
            
            if debug:
                print("Consistency verification successful!")

            return True
            
        except Exception as e:
            if debug:
                print(f"Consistency verification failed: {e}")

            return False
            
    except Exception as e:
        if debug:
            print(f"Error during consistency verification: {e}")
        return False

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion_result = inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
