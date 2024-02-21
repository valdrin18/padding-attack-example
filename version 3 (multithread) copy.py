import os
import requests
import concurrent.futures

BLOCK_SIZE = 14

url_base = os.getenv("URL", "")

session = requests.Session()  # Keep a persistent connection

def padding_oracle(iv, block):
    url = f"{url_base}{iv.hex()}{block.hex()}"
    response = session.get(url)
    return response.status_code != 400

def single_block_attack(iv, block):
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        print(f"Trying padding value {pad_val}...")
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            print(f"\tTrying byte candidate: {candidate}")
            padding_iv[-pad_val] = candidate
            iv_byte_array = bytes(padding_iv)
            if padding_oracle(iv_byte_array, block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv_byte_array = bytes(padding_iv)
                    if not padding_oracle(iv_byte_array, block):
                        continue
                break

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

def decrypt_block(args):
    index, iv, ct = args
    print(f"\nDecoding block {index}...")
    dec = single_block_attack(iv, ct)
    pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
    return pt

def full_attack(iv, ct):
    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    args = [(index, blocks[index-1], block) for index, block in enumerate(blocks[1:], start=1)]

    decrypted_parts = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        decrypted_parts = list(executor.map(decrypt_block, args))

    return b''.join(decrypted_parts)

def decrypt_ciphertext(ciphertext):
    iv = bytes.fromhex(ciphertext[:BLOCK_SIZE * 2])
    ct = bytes.fromhex(ciphertext[BLOCK_SIZE * 2:])
    decrypted = full_attack(iv, ct)
    pad_length = decrypted[-1]
    return decrypted[:-pad_length].decode()

if __name__ == "__main__":
    ciphertext_segment = ""
    secret = decrypt_ciphertext(ciphertext_segment)
    print(secret, end='')
