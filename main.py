import argparse
import json
import base64
from sigstore.sign import RekorClient
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    """
    Retrieve a log entry from the Rekor transparency log by index using sigstore-python.
    
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
        # if debug and log_entry:
        #     print(f"Successfully retrieved log entry {log_index}")
        #     print(f"Log entry UUID: {log_entry.uuid}")
        #     print(f"Log index: {log_entry.log_index}")
        #     print(f"Integrated time: {log_entry.integrated_time}")
        #     print(f"Log ID: {log_entry.log_id}")
        #     if hasattr(log_entry, 'body'):
        #         print(f"Body (Base64): {log_entry.body}")
        return log_entry
            
    except Exception as e:
        if debug:
            print(f"Error occurred while fetching log entry {log_index}: {e}")
            print(f"Error type: {type(e).__name__}")
        return None

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    pass

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
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
    result = verify_artifact_signature(signature_bytes, extracted_public_key, "/Users/sankalpramesh/cs-9223-assignment-1/artifact.md")
    print("Signature verification result:", result)
    
    # Extract verification data for inclusion proof
    inclusion_proof = log_entry.inclusion_proof
    if inclusion_proof:
        # Extract the required values
        index = inclusion_proof.log_index
        tree_size = inclusion_proof.tree_size
        root_hash = inclusion_proof.root_hash if inclusion_proof.root_hash else None
        hashes = inclusion_proof.hashes if inclusion_proof.hashes else []
        tree_size = inclusion_proof.tree_size
        return verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash) == None
            
def get_latest_checkpoint(debug=False):
    """
    Get the latest checkpoint from the Rekor transparency log.
    
    Args:
        debug (bool): Enable debug output
        
    Returns:
        dict: Checkpoint data including tree ID, tree size, root hash
    """
    if debug:
        print("Retrieving latest checkpoint from Rekor server...")
    
    try:
        # Create Rekor client
        rekor_client = RekorClient("https://rekor.sigstore.dev/")
        
        # Get log information (includes checkpoint data)
        log_info = rekor_client.log.get()
        
        # Structure checkpoint data
        checkpoint = {
            "treeID": log_info.tree_id,
            "treeSize": log_info.tree_size,
            "rootHash": log_info.root_hash,
            "signedTreeHead": log_info.signed_tree_head
        }
        
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
        return None

def consistency(prev_checkpoint, debug=False):
    """
    Verify consistency between a previous checkpoint and the latest checkpoint.
    
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
        
        if prev_size > latest_size:
            if debug:
                print(f"Invalid: previous size ({prev_size}) > latest size ({latest_size})")
            return False
        
        if prev_size == latest_size:
            # Same size, should have same root hash
            if prev_checkpoint['rootHash'] == latest_checkpoint['rootHash']:
                if debug:
                    print("Consistency verified: identical tree states")
                return True
            else:
                if debug:
                    print("Inconsistency detected: same size but different root hashes")
                return False
        
        # Get consistency proof using sigstore client
        rekor_client = RekorClient("https://rekor.sigstore.dev/")
        proof_endpoint = "log/proof"
        params = {
            'firstSize': prev_size,
            'lastSize': latest_size
        }
        
        if debug:
            print(f"Requesting consistency proof using sigstore client with params: {params}")
        
        response = rekor_client.session.get(f"{rekor_client.url}{proof_endpoint}", params=params)
        
        if response.status_code != 200:
            if debug:
                print(f"Failed to get consistency proof: HTTP {response.status_code}")
                print(f"Response: {response.text}")
            return False
        
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
        inclusion(args.inclusion, args.artifact, debug)
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
