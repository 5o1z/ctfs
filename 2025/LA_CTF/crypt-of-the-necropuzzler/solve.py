import pexpect
import time

def solve_puzzle():
    # Start the puzzle process
    child = pexpect.spawn('python3 crypt-of-the-necropuzzler.py')
    time.sleep(1)  # Allow time for initialization
    
    # Solution sequence: precise toggles and path
    commands = [
        "d", "d", "s", "s", "x",  # Move to (2,2) and toggle
        "a", "a", "s", "s", "x",  # Move to (4,0) and toggle
        "d", "d", "x",  # Move to (4,2) and toggle
        "s", "d", "x",  # Move to (5,3) and toggle
        "a", "a", "s", "x",  # Move to (6,1) and toggle
        "d", "d", "x",  # Move to (6,3) and toggle
        "s", "a", "a", "x",  # Move to (7,1) and toggle
        "d", "d", "c"  # Move to (7,3) and check
    ]
    
    # Send commands
    for command in commands:
        child.send(command)
        time.sleep(0.1)  # Allow time for updates
    
    # Allow interaction to see output
    child.interact()

if __name__ == "__main__":
    solve_puzzle()