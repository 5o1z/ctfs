#!/usr/bin/env python3

import sys

def xor_file(input_file, key, output_file="result.txt"):
    """
    XOR each byte in the input file with the provided key value
    and write the result to the output file.
    
    Args:
        input_file (str): Path to the input file
        key (int): Value to XOR with (0-255)
        output_file (str): Path to the output file (default: result.txt)
    """
    try:
        # Convert key to integer if it's not already
        key = int(key) % 256  # Ensure key is in byte range (0-255)
        
        # Read input file as binary
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
        
        # XOR each byte with the key
        xored_data = bytearray()
        for byte in data:
            xored_byte = byte ^ key
            xored_data.append(xored_byte)
        
        # Write the result to output file
        with open(output_file, 'wb') as f_out:
            f_out.write(xored_data)
            
        print(f"XOR operation completed. Result written to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
    except ValueError:
        print("Error: Key must be a valid integer")
    except Exception as e:
        print(f"Error: {e}")
        
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python xor_file.py <input_file> <key> [output_file]")
        print("  <input_file>: The file to process")
        print("  <key>: XOR key value (0-255)")
        print("  [output_file]: Optional output file name (default: result.txt)")
        sys.exit(1)
    
    input_file = sys.argv[1]
    key = sys.argv[2]
    
    # Check if output file is specified
    if len(sys.argv) > 3:
        output_file = sys.argv[3]
    else:
        output_file = "result.txt"
    
    xor_file(input_file, key, output_file)