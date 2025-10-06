# Binary Analysis Report: BabyHeap Challenge

## Overview

This is a heap management challenge binary ("Book Factory") that implements a simple book storage system with classic heap exploitation vulnerabilities. The binary allows users to add, remove, and view book content stored in dynamically allocated memory.

## Binary Metadata

- **File**: `chall`
- **Architecture**: x86-64 Linux ELF
- **Size**: 0x40f0 bytes (16,624 bytes)
- **Base Address**: 0x0
- **MD5**: b004504623ea939d9dd4b05df84c4ea1
- **SHA256**: 2189d1c2961c6d861648712f2b416cc644b2c7ebe9e2b6891845ae709e9a1994

## Program Architecture

### Main Data Structure

The program uses a global array `book_array[10]` of the following structure:

```c
struct book_entry {
    int64_t is_free;    // 0 = allocated, 1 = free
    size_t size;        // Size of allocated memory
    char *content;      // Pointer to content
};
```

Each book entry occupies 24 bytes (3 * 8 bytes) and the array can hold up to 10 books (indices 0-9).

### Key Functions

#### 1. `init_program()` (0x1289)
- **Purpose**: Initialize program environment
- **Functionality**:
  - Disables buffering for stdin, stdout, and stderr using `setvbuf()`
  - Ensures immediate I/O for interactive usage

#### 2. `display_menu()` (0x1315)
- **Purpose**: Display user menu options
- **Functionality**: Shows 4 options:
  1. Add book
  2. Remove book
  3. Show book content
  4. Exit

#### 3. `main()` (0x1397)
- **Purpose**: Main program loop and menu handling
- **Functionality**:
  - Initializes program
  - Enters infinite loop with menu processing
  - Handles user choice via switch statement
  - Implements all core functionality

## Functionality Analysis

### Case 1: Add Book
```c
// 1. Get book index and validate (VULNERABILITY HERE)
if (book_index > 0xA) goto invalid_index;  // Should be >= 0xA

// 2. Get book size
if (book_size > 0) {
    // 3. Store size and allocate memory
    book_array[book_index].size = book_size;
    book_array[book_index].content = malloc(book_size);

    // 4. Read content and mark as allocated
    read(0, book_array[book_index].content, book_size);
    book_array[book_index].is_free = 0;
}
```

### Case 2: Remove Book
```c
// 1. Get book index and validate
if (book_index <= 0xA) {
    // 2. Free memory and mark as freed
    free(book_array[book_index].content);  // VULNERABILITY: No null check
    book_array[book_index].is_free = 1;
}
```

### Case 3: Show Book Content
```c
// 1. Get book index and validate (correct bounds check)
if (book_index >= 0xA) goto invalid_index;

// 2. Check if book exists and display
if (book_array[book_index].is_free == 1)
    puts("No book at this index!");
else
    printf("Content: %s\n", book_array[book_index].content);
```

## Vulnerabilities Identified

### 1. Off-by-One Buffer Overflow (Critical)
- **Location**: Add book functionality (0x145f)
- **Issue**: Bounds check uses `> 0xA` instead of `>= 0xA`
- **Impact**: Allows writing to `book_array[10]`, which is out of bounds
- **Exploitation**: Can overwrite adjacent memory, potentially leading to:
  - Heap metadata corruption
  - Function pointer overwrites
  - Control flow hijacking

### 2. Use-After-Free (High)
- **Location**: Remove book functionality (0x1641)
- **Issue**: `free()` is called but pointer is not nullified
- **Impact**: Freed memory can still be accessed via show/add operations
- **Exploitation**: Can lead to:
  - Information disclosure
  - Heap feng shui attacks
  - Double-free scenarios

### 3. Buffer Overflow Potential (Medium)
- **Location**: Content reading (0x159c)
- **Issue**: `read()` reads exact size without null termination
- **Impact**: If content is treated as string, no null terminator guaranteed
- **Exploitation**: Can cause information disclosure when printing content

### 4. Double-Free Potential (Medium)
- **Location**: Remove book functionality
- **Issue**: No check if book is already freed before calling `free()`
- **Impact**: Calling `free()` on already freed memory
- **Exploitation**: Can corrupt heap metadata and lead to crashes or RCE

## Heap Exploitation Strategy

### Primary Attack Vector: Off-by-One Overflow
1. **Target**: `book_array[10]` out-of-bounds write
2. **Method**: Use index 10 in add book operation
3. **Goal**: Overwrite heap metadata or function pointers
4. **Steps**:
   - Add book at index 10 (triggers off-by-one)
   - Overwrite adjacent memory with controlled data
   - Trigger use of corrupted data for code execution

### Secondary Attack Vector: Use-After-Free
1. **Setup**: Allocate book, free it, then reallocate same size
2. **Method**: Create heap confusion with multiple allocations/frees
3. **Goal**: Control freed memory contents
4. **Steps**:
   - Allocate book A
   - Free book A (pointer still accessible)
   - Allocate book B (reuses A's memory)
   - Use book A's stale pointer to read B's content

## Code Quality Assessment

### Strengths
- Clear structure separation
- Consistent error handling for invalid inputs
- Proper stack canary usage

### Weaknesses
- Multiple bounds checking inconsistencies
- No pointer validation after `free()`
- Missing null termination handling
- No size validation for extremely large allocations

## Recommended Mitigations

1. **Fix bounds checking**: Use `>= 0xA` consistently
2. **Null pointers after free**: Set `content = NULL` after `free()`
3. **Add double-free protection**: Check if already freed before calling `free()`
4. **Validate pointers**: Check for NULL before dereferencing
5. **Add size limits**: Prevent extremely large allocations
6. **Null-terminate strings**: Ensure content is properly null-terminated

## Renamed Variables and Functions

### Functions Renamed:
- `setup` → `init_program`: Better describes the initialization functionality
- `menu` → `display_menu`: Clarifies that it only displays the menu

### Variables Renamed:
- `n4` → `choice`: Menu choice variable
- `n0xA` → `book_index`: Book array index
- `size` → `book_size`: Size of book content
- `book` → `book_array`: Global array of book entries

### Structure Defined:
- Created `book_entry` struct to replace raw memory accesses
- Applied struct type to global `book_array[10]`

## Conclusion

This is a classic heap exploitation challenge featuring multiple vulnerability classes commonly found in CTF heap challenges. The off-by-one vulnerability provides the primary attack vector, while use-after-free offers additional exploitation opportunities. The binary is well-suited for learning heap exploitation techniques and demonstrates common programming mistakes that lead to security vulnerabilities.
