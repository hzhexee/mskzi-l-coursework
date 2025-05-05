import struct
import os
import time
import hashlib
import hmac
import random
import json
import math

# Try to import pyautogui for mouse position entropy
try:
    import pyautogui
    HAVE_PYAUTOGUI = True
except ImportError:
    HAVE_PYAUTOGUI = False


def yield_chacha20_xor_stream(key, iv, position=0):
  """Generate the xor stream with the ChaCha20 cipher."""
  if not isinstance(position, int):
    raise TypeError
  if position & ~0xffffffff:
    raise ValueError('Position is not uint32.')
  if not isinstance(key, bytes):
    raise TypeError
  if not isinstance(iv, bytes):
    raise TypeError
  if len(key) != 32:
    raise ValueError
  if len(iv) != 8:
    raise ValueError

  def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)

  def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)

  ctx = [0] * 16
  ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
  ctx[4 : 12] = struct.unpack('<8L', key)
  ctx[12] = ctx[13] = position
  ctx[14 : 16] = struct.unpack('<LL', iv)
  while 1:
    x = list(ctx)
    for i in range(10):
      quarter_round(x, 0, 4,  8, 12)
      quarter_round(x, 1, 5,  9, 13)
      quarter_round(x, 2, 6, 10, 14)
      quarter_round(x, 3, 7, 11, 15)
      quarter_round(x, 0, 5, 10, 15)
      quarter_round(x, 1, 6, 11, 12)
      quarter_round(x, 2, 7,  8, 13)
      quarter_round(x, 3, 4,  9, 14)
    for c in struct.pack('<16L', *(
        (x[i] + ctx[i]) & 0xffffffff for i in range(16))):
      yield c
    ctx[12] = (ctx[12] + 1) & 0xffffffff
    if ctx[12] == 0:
      ctx[13] = (ctx[13] + 1) & 0xffffffff


def chacha20_encrypt(data, key, iv=None, position=0):
  """Encrypt (or decrypt) with the ChaCha20 cipher."""
  if not isinstance(data, bytes):
    raise TypeError
  if iv is None:
    iv = b'\0' * 8
  if isinstance(key, bytes):
    if not key:
      raise ValueError('Key is empty.')
    if len(key) < 32:
      key = (key * (32 // len(key) + 1))[:32]
    if len(key) > 32:
      raise ValueError('Key too long.')

  return bytes(a ^ b for a, b in
      zip(data, yield_chacha20_xor_stream(key, iv, position)))


def chacha20_decrypt(data, key, iv=None, position=0):
    """Decrypt with the ChaCha20 cipher (same as encrypt due to XOR properties)."""
    return chacha20_encrypt(data, key, iv, position)


def generate_key(salt=None):
    """
    Generate a secure 32-byte key using multiple entropy sources and HKDF.
    
    Args:
        salt (bytes, optional): Salt for key derivation. If None, a random salt is generated.
        
    Returns:
        tuple: (key, salt) - The generated 32-byte key and the salt used
    """
    # Collect entropy
    entropy = bytearray()
    
    # System time as entropy source
    entropy.extend(str(time.time_ns()).encode())
    
    # Mouse position as entropy source
    if HAVE_PYAUTOGUI:
        try:
            x, y = pyautogui.position()
            entropy.extend(str(x).encode() + b"," + str(y).encode())
        except Exception:
            # Fallback if mouse position cannot be obtained
            entropy.extend(os.urandom(4))
    else:
        # Additional entropy if pyautogui is not available
        entropy.extend(os.urandom(8))
    
    # More system entropy
    entropy.extend(os.urandom(16))
    
    # Process ID and thread ID as additional entropy
    import threading
    entropy.extend(str(os.getpid()).encode() + str(threading.get_ident).encode())
    
    # Generate or use provided salt
    if salt is None:
        salt = os.urandom(16)
    
    # Apply HKDF (HMAC-based Key Derivation Function)
    def hkdf(input_key_material, salt, info=b"ChaCha20Key", length=32):
        """HKDF implementation based on RFC 5869"""
        # HKDF-Extract
        if not salt:
            salt = bytes([0] * hashlib.sha256().digest_size)
        prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
        
        # HKDF-Expand
        t = b""
        okm = b""
        for i in range(1, (length // hashlib.sha256().digest_size) + 2):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:length]
    
    # Generate the key using HKDF
    key = hkdf(bytes(entropy), salt)
    
    return key, salt


def derive_block_key(master_key, block_id, nonce):
    """
    Derive a unique key for a specific block using the master key and block ID.
    
    Args:
        master_key (bytes): The master encryption key
        block_id (int): The unique identifier for the block
        nonce (bytes): Nonce value for key derivation
        
    Returns:
        bytes: A derived 32-byte key unique to this block
    """
    # Create a unique info string for this block
    info = f"Block{block_id}".encode() + nonce
    
    # Use HKDF to derive a unique key
    def hkdf(key, salt, info, length=32):
        """HKDF implementation based on RFC 5869"""
        # HKDF-Extract
        if not salt:
            salt = bytes([0] * hashlib.sha256().digest_size)
        prk = hmac.new(salt, key, hashlib.sha256).digest()
        
        # HKDF-Expand
        t = b""
        okm = b""
        for i in range(1, (length // hashlib.sha256().digest_size) + 2):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:length]
    
    return hkdf(master_key, nonce, info)


def shuffle_blocks(blocks, seed):
    """
    Shuffle blocks using a deterministic algorithm based on a seed.
    
    Args:
        blocks (list): List of blocks to shuffle
        seed (bytes or int): Seed for the random number generator
        
    Returns:
        tuple: (shuffled_blocks, block_map) where block_map maps new positions to original positions
    """
    # Create a copy of the blocks to shuffle
    blocks_copy = blocks.copy()
    
    # Convert seed to integer if it's bytes
    if isinstance(seed, bytes):
        seed = int.from_bytes(seed, byteorder='big')
    
    # Create a deterministic random number generator
    rng = random.Random(seed)
    
    # Shuffle the blocks
    rng.shuffle(blocks_copy)
    
    # Create a mapping from new positions to original positions
    block_map = {}
    for new_pos, block in enumerate(blocks_copy):
        # Find the original position of this block
        orig_pos = blocks.index(block)
        block_map[new_pos] = orig_pos
    
    return blocks_copy, block_map


def unshuffle_blocks(shuffled_blocks, block_map):
    """
    Restore the original order of blocks using the block map.
    
    Args:
        shuffled_blocks (list): List of shuffled blocks
        block_map (dict): Mapping from shuffled positions to original positions
        
    Returns:
        list: Blocks in their original order
    """
    # Create an empty list with the same length as the shuffled blocks
    original_blocks = [None] * len(shuffled_blocks)
    
    # Put each block in its original position
    for new_pos, orig_pos in block_map.items():
        original_blocks[orig_pos] = shuffled_blocks[new_pos]
    
    return original_blocks


def encrypt_file(input_path, output_path, key=None, salt=None, block_size=102400):
    """
    Encrypt a file using ChaCha20 with block processing and shuffling.
    
    Args:
        input_path (str): Path to the input file
        output_path (str): Path to save the encrypted file
        key (bytes, optional): Encryption key. If None, a new key is generated
        salt (bytes, optional): Salt for key derivation. If None, a new salt is generated
        block_size (int, optional): Size of each block in bytes. Default is 100 KB
        
    Returns:
        tuple: (key, salt) used for encryption
    """
    # Generate or use provided key and salt
    if key is None or salt is None:
        key, salt = generate_key(salt)
    
    # Read the input file
    with open(input_path, 'rb') as f:
        file_data = f.read()
    
    # Split the file into blocks
    blocks = []
    for i in range(0, len(file_data), block_size):
        block = file_data[i:i + block_size]
        blocks.append(block)
    
    # Create a nonce for shuffling seed and key derivation
    nonce = os.urandom(8)
    shuffle_seed = hashlib.sha256(key + nonce + b"shuffle").digest()
    
    # Encrypt each block with a unique key derived from the block ID
    encrypted_blocks = []
    for block_id, block in enumerate(blocks):
        # Derive a unique key for this block
        block_key = derive_block_key(key, block_id, nonce)
        
        # Create a unique IV for this block
        block_iv = hashlib.sha256(nonce + str(block_id).encode()).digest()[:8]
        
        # Encrypt the block
        encrypted_block = chacha20_encrypt(block, block_key, block_iv)
        encrypted_blocks.append(encrypted_block)
    
    # Shuffle the encrypted blocks
    shuffled_blocks, block_map = shuffle_blocks(encrypted_blocks, shuffle_seed)
    
    # Create metadata
    metadata = {
        'salt': salt.hex(),
        'nonce': nonce.hex(),
        'num_blocks': len(blocks),
        'block_map': {str(k): v for k, v in block_map.items()},  # Convert keys to strings for JSON serialization
        'original_file_size': len(file_data)
    }
    
    # Convert metadata to JSON and encrypt it
    metadata_json = json.dumps(metadata).encode()
    metadata_key = hashlib.sha256(key + b"metadata").digest()
    metadata_iv = hashlib.sha256(nonce + b"metadata").digest()[:8]
    encrypted_metadata = chacha20_encrypt(metadata_json, metadata_key, metadata_iv)
    
    # Write the encrypted file
    with open(output_path, 'wb') as f:
        # Write the nonce unencrypted at the beginning so we can use it for metadata decryption
        f.write(nonce)
        
        # Write metadata length as a 4-byte integer
        f.write(len(encrypted_metadata).to_bytes(4, byteorder='big'))
        
        # Write encrypted metadata
        f.write(encrypted_metadata)
        
        # Write all shuffled blocks
        for block in shuffled_blocks:
            # Write block length as a 4-byte integer
            f.write(len(block).to_bytes(4, byteorder='big'))
            f.write(block)
    
    return key, salt


def decrypt_file(input_path, output_path, key, salt=None):
    """
    Decrypt a file encrypted with encrypt_file.
    
    Args:
        input_path (str): Path to the encrypted file
        output_path (str): Path to save the decrypted file
        key (bytes): Decryption key
        salt (bytes, optional): Salt used for encryption (not actually needed as it's stored in metadata)
        
    Returns:
        bool: True if decryption was successful
    """
    # Read the encrypted file
    with open(input_path, 'rb') as f:
        # First read the nonce (8 bytes) that was written unencrypted
        nonce = f.read(8)
        
        # Read metadata length
        metadata_length = int.from_bytes(f.read(4), byteorder='big')
        
        # Read and decrypt metadata
        encrypted_metadata = f.read(metadata_length)
        metadata_key = hashlib.sha256(key + b"metadata").digest()
        metadata_iv = hashlib.sha256(nonce + b"metadata").digest()[:8]  # Now using the correct nonce
        
        # Try to decrypt metadata - this might fail if the key is wrong
        try:
            metadata_json = chacha20_decrypt(encrypted_metadata, metadata_key, metadata_iv)
            metadata = json.loads(metadata_json.decode())
            
            # Extract metadata
            salt = bytes.fromhex(metadata['salt'])
            num_blocks = metadata['num_blocks']
            block_map = {int(k): v for k, v in metadata['block_map'].items()}  # Convert keys back to integers
            original_file_size = metadata['original_file_size']
        except Exception as e:
            print(f"Error decrypting metadata: {e}")
            return False
        
        # Read all blocks
        shuffled_blocks = []
        for _ in range(num_blocks):
            try:
                # Read block length
                block_length = int.from_bytes(f.read(4), byteorder='big')
                
                # Read block
                block = f.read(block_length)
                shuffled_blocks.append(block)
            except Exception as e:
                print(f"Error reading block: {e}")
                return False
    
    # Calculate shuffle seed
    shuffle_seed = hashlib.sha256(key + nonce + b"shuffle").digest()
    
    # Unshuffle blocks (we have the block_map from metadata)
    encrypted_blocks = [None] * num_blocks
    for new_pos, orig_pos in block_map.items():
        if new_pos < len(shuffled_blocks):
            encrypted_blocks[orig_pos] = shuffled_blocks[new_pos]
    
    # Decrypt each block
    decrypted_blocks = []
    for block_id, block in enumerate(encrypted_blocks):
        if block is None:
            print(f"Warning: Block {block_id} is missing")
            continue
            
        # Derive the same unique key for this block
        block_key = derive_block_key(key, block_id, nonce)
        
        # Create the same unique IV for this block
        block_iv = hashlib.sha256(nonce + str(block_id).encode()).digest()[:8]
        
        # Decrypt the block
        decrypted_block = chacha20_decrypt(block, block_key, block_iv)
        decrypted_blocks.append(decrypted_block)
    
    # Combine blocks and write the output file
    with open(output_path, 'wb') as f:
        # Write all decrypted blocks
        for block in decrypted_blocks:
            f.write(block)
        
        # Truncate to original file size if needed
        f.truncate(original_file_size)
    
    return True

