# Stack Note Binary Analysis

## Overview

The `prob` binary is a simple note-taking application written in C that allows users to create, read, update, and delete notes. The application uses a stack-based array to store up to 10 notes, each with a maximum data size of 40 bytes.

## Program Architecture

### Data Structure

The program defines a `note` structure:
```c
struct note {
    size_t size;        // 8 bytes - size of the data
    char data[40];      // 40 bytes - note content
};                      // Total: 48 bytes per note
```

The main function allocates an array of 10 notes on the stack:
```c
note notes[10];  // 480 bytes total (10 * 48)
```

### Main Program Flow

1. **Initialization**: Sets up buffering for stdin, stdout, and stderr
2. **Menu Loop**: Presents a menu with 4 options:
   - 1. Create note
   - 2. Read note
   - 3. Update note
   - 4. Delete note
3. **Input Processing**: Uses `scanf()` to read user choice and dispatches to appropriate function

## Function Analysis

### `main()` - Entry Point
- **Purpose**: Initializes the program and handles the main menu loop
- **Stack Layout**: 480-byte note array + stack canary protection
- **Security**: Uses stack canaries for protection against buffer overflows

### `create_note(note *notes)` - Note Creation
- **Purpose**: Creates a new note in the first available slot
- **Process**:
  1. Finds first empty slot (where `size == 0`)
  2. Prompts for note size
  3. Validates size is ≤ 40 bytes
  4. Reads note data using `read()` syscall
- **Vulnerabilities**:
  - **Integer overflow**: `scanf("%ld", &notes[index].size)` can accept negative values
  - **Bounds checking**: Only validates upper bound (40), not lower bound

### `read_note(note *notes)` - Note Reading
- **Purpose**: Displays the content of a specified note
- **Process**:
  1. Prompts for note index
  2. Validates index (0-9) and checks if note exists
  3. Uses `write()` syscall to output note data
- **Security**: Proper bounds checking implemented

### `update_note(note *notes)` - Note Modification
- **Purpose**: Updates the size and data of an existing note
- **Process**:
  1. Prompts for note index
  2. Validates index and note existence
  3. Prompts for new size and validates ≤ 40 bytes
  4. Reads new data using `read()` syscall
- **Vulnerabilities**:
  - **Integer overflow**: Same scanf issue as create_note
  - **Information disclosure**: Old data is not cleared before writing new data
  - **Size inconsistency**: Can change size without clearing previous data

### `delete_note(note *notes)` - Note Deletion
- **Purpose**: Marks a note as deleted by setting size to 0
- **Process**:
  1. Prompts for note index
  2. Validates index and note existence
  3. Sets `notes[index].size = 0`
- **Vulnerabilities**:
  - **Use-after-free potential**: Only clears size field, data remains in memory
  - **Information disclosure**: Deleted note data can still be accessed if size is manipulated

## Security Analysis

### Identified Vulnerabilities

1. **Integer Overflow in Size Field**
   - **Location**: `create_note()` and `update_note()` functions
   - **Cause**: `scanf("%ld", &size)` accepts negative values
   - **Impact**: Could bypass size validation checks
   - **Exploitation**: Set negative size to bypass 40-byte limit

2. **Information Disclosure**
   - **Location**: `delete_note()` and `update_note()` functions
   - **Cause**: Data not properly cleared
   - **Impact**: Sensitive data remains accessible
   - **Exploitation**: Read deleted note data or partially overwrite notes

3. **Potential Buffer Overflow**
   - **Location**: Combined with integer overflow
   - **Cause**: Negative size values could lead to large reads
   - **Impact**: Stack buffer overflow
   - **Exploitation**: If size is set to a large negative value (interpreted as large positive), could overflow the 40-byte buffer

### Security Mitigations Present

1. **Stack Canaries**: Present in all functions with local buffers
2. **Input Validation**: Basic bounds checking for note indices
3. **Size Limits**: 40-byte maximum for note data (when positive)

### Attack Vectors

1. **Integer Overflow Exploitation**:
   ```
   1. Create note with negative size (e.g., -1)
   2. This bypasses the size > 40 check
   3. When interpreted as unsigned, becomes very large
   4. Could lead to buffer overflow during read()
   ```

2. **Information Disclosure**:
   ```
   1. Create note with max size (40 bytes)
   2. Delete the note (only size cleared)
   3. Create new note with smaller size
   4. Read note to see old data beyond new size
   ```

## Recommendations

1. **Fix Integer Overflow**: Validate that size is positive before any operations
2. **Secure Memory Management**: Clear note data on deletion
3. **Input Validation**: Add stricter input validation for all user inputs
4. **Use Safe Functions**: Replace `scanf()` with safer alternatives like `fgets()`

## Technical Details

- **Binary Type**: ELF 64-bit LSB executable
- **Architecture**: x86-64
- **Compiler Protections**: Stack canaries enabled
- **ASLR**: Likely enabled (system dependent)
- **DEP/NX**: Likely enabled (system dependent)

## Renamed Variables and Functions

All functions have been refactored for clarity:

- **Variables**:
  - `buf` → `notes` (note array)
  - `n4` → `choice` (menu selection)
  - `n9` → `index` (note index)
  - `v3`, `v6` → `stack_canary` (stack protection)

- **Function Parameters**: Updated to use proper `note *` types instead of generic `__int64`

- **Structure**: Defined proper `struct note` with `size` and `data[40]` fields

## Conclusion

This is a classic vulnerable note-taking application with multiple security issues primarily stemming from improper input validation and memory management. The most critical vulnerability is the integer overflow in size handling, which could potentially lead to buffer overflow exploitation. The application would benefit from comprehensive input validation and secure memory management practices.
