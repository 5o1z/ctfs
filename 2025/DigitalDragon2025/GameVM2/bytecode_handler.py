#!/usr/bin/env python3
"""
Phase 2: VM Host Exploitation Challenge
Bytecode Handler - Accepts hex-encoded bytecode and runs it in VM host
"""

import sys
import os
import tempfile
import subprocess
import binascii
import random
import string
import signal
import time

# Author: l4w

# Ensure output is always flushed (important for xinetd)
import functools
print = functools.partial(print, flush=True)

def signal_handler(signum, frame):
    """Handle timeout signal"""
    print("\n[DEBUG] Timeout reached. Exiting...")
    sys.exit(1)

def main():
    # Set execution timeout
    print("[DEBUG] Setting SIGALRM handler and 60s alarm")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(60)  # 60 second timeout
    
    print("=== Phase 2: VM Host Exploitation Challenge ===")
    print("Send your hex-encoded bytecode:")
    print("Format: CAFE8386<code_size><data_size><encrypted_code><data>")
    print("")
    
    try:
        # Read hex input from stdin instead of input()
        print("[DEBUG] Waiting for user input from stdin...")
        sys.stdout.write("Hex bytecode: ")
        sys.stdout.flush()
        hex_input = sys.stdin.readline()
        if hex_input is not None:
            hex_input = hex_input.strip()
        else:
            hex_input = ""
        print(f"[DEBUG] Received input: {hex_input}")
        
        if not hex_input:
            print("[DEBUG] No input provided")
            print("Error: No input provided")
            return
        
        # Validate hex input
        if len(hex_input) % 2 != 0:
            print(f"[DEBUG] Input length is odd: {len(hex_input)}")
            print("Error: Invalid hex string (odd length)")
            return
        
        # Convert hex to bytes
        try:
            print("[DEBUG] Attempting to decode hex input...")
            bytecode = binascii.unhexlify(hex_input)
            print(f"[DEBUG] Decoded bytecode length: {len(bytecode)}")
        except binascii.Error as e:
            print(f"[DEBUG] binascii.Error: {e}")
            print(f"Error: Invalid hex format - {e}")
            return
        
        # Validate minimum length (header is 8 bytes)
        if len(bytecode) < 8:
            print(f"[DEBUG] Bytecode too short: {len(bytecode)} bytes")
            print("Error: Bytecode too short (minimum 8 bytes for header)")
            return
        
        # Create temporary file with random name
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        temp_file = f"/tmp/bytecode_{random_suffix}.bin"
        print(f"[DEBUG] Temporary file path: {temp_file}")
        
        # Write bytecode to temporary file
        try:
            with open(temp_file, 'wb') as f:
                f.write(bytecode)
            print(f"[DEBUG] Successfully wrote bytecode to {temp_file}")
        except Exception as e:
            print(f"[DEBUG] Failed to write bytecode to file: {e}")
            print(f"Error: Could not write bytecode to file: {e}")
            return
        
        print(f"Bytecode saved to {temp_file}")
        print(f"Size: {len(bytecode)} bytes")
        print("")
        print("=== Executing in VM Host ===")
        print(f"[DEBUG] Running: /home/ctf/vm_host {temp_file}")
        
        # Execute VM host with the bytecode
        try:
            # Use subprocess.Popen to stream output directly to sys.stdout/stderr with no buffering
            with subprocess.Popen(
                ['/home/ctf/vm_host', temp_file],
                stdout=sys.stdout,
                stderr=sys.stderr,
                bufsize=0,
                text=True
            ) as proc:
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    print("[DEBUG] VM execution timed out")
                    print("Error: VM execution timed out")
                    return
                print(f"[DEBUG] VM host process completed. Return code: {proc.returncode}")
            print(f"[DEBUG] VM host process completed. Return code: {result.returncode}")
            print(f"[DEBUG] STDOUT length: {len(result.stdout) if result.stdout else 0}")
            print(f"[DEBUG] STDERR length: {len(result.stderr) if result.stderr else 0}")
            
            # Print output
            if result.stdout:
                print("STDOUT:")
                print(result.stdout)
            
            if result.stderr:
                print("STDERR:")
                print(result.stderr)
            
            print(f"Exit code: {result.returncode}")
            
        except subprocess.TimeoutExpired:
            print("[DEBUG] VM execution timed out")
            print("Error: VM execution timed out")
        except Exception as e:
            print(f"[DEBUG] Exception during VM execution: {e}")
            print(f"Error executing VM host: {e}")
        
    except KeyboardInterrupt:
        print("\n[DEBUG] Interrupted by user")
        print("\nInterrupted by user")
    except Exception as e:
        print(f"[DEBUG] Exception in main: {e}")
        print(f"Error: {e}")
    finally:
        # Cleanup temporary file
        try:
            if 'temp_file' in locals():
                print(f"[DEBUG] Cleaning up temporary file: {temp_file}")
                os.unlink(temp_file)
        except Exception as e:
            print(f"[DEBUG] Failed to clean up temporary file: {e}")

if __name__ == "__main__":
    print("[DEBUG] Starting bytecode handler main()")
    main() 
