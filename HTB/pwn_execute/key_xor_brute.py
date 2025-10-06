def xor_brute_force(target, bad_bytes):
    """
    Brute force to find a key that XORs with the target value to produce a result with no bad bytes.

    :param target: The integer value to XOR against (e.g., 0x68732f6e69622f).
    :param bad_bytes: A set of byte values to avoid in the result (e.g., {0x3b, 0x54, ...}).
    :return: A tuple (key, result) where the key is the found key and the result is the XOR-ed value.
    """
    target_bytes = target.to_bytes((target.bit_length() + 7) // 8, 'big')

    # Iterate over possible keys (e.g., 8-byte values)
    for key in range(1, 0xFFFFFFFFFFFFFFFF):  # Avoid 0 as a key since it would result in null bytes.
        key_bytes = key.to_bytes(len(target_bytes), 'big', signed=False)

        # Perform XOR
        result = bytes(a ^ b for a, b in zip(target_bytes, key_bytes))

        # Check for bad bytes in the result
        if all(byte not in bad_bytes for byte in result):
            return key, result

    return None, None

# Example usage
if __name__ == "__main__":
    target_value = 0x68732f6e69622f  # Target value to XOR with
    bad_byte_values = {0x3b, 0x54, 0x62, 0x69, 0x6e, 0x73, 0x68, 0xf6, 0xd2, 0xc0, 0x5f, 0xc9, 0x66, 0x6c, 0x61, 0x67}  # Bytes to avoid

    key, result = xor_brute_force(target_value, bad_byte_values)

    if key:
        print(f"Found key: {key:#x}")
        print(f"Result: {result.hex()}")
    else:
        print("No valid key found.")