	# Checks - Advanced System Diagnostic & Debugging Tool

A powerful C-based debugger and diagnostic tool for Windows that can run executables under monitoring, perform memory stress testing, and analyze disk performance at a low level.

## Features

(START OF AI USAGE)

**Executable Debugger** - Loads and runs executables under checks' own debugger (like GDB)

**Memory Stress Testing** - Continuous allocation loop with safety protocol

**Low-Level Disk Analysis** - Direct disk I/O testing and geometry analysis

**Command PATH Verification** - Check if commands are available

**Activity Logging** - Timestamped log of all operations

**Keyboard Shortcuts** - Ctrl+C failsafe, Ctrl+E quick exit

**Interactive Shell** - Command-line interface with help system

## What Makes This Different

This is **NOT a wrapper program** - it implements its own checking logic:

- **check exec**: it loads the PE file, validates headers, creates the process under DEBUG_PROCESS mode, and monitors every system event (process creation, DLL loads, exceptions, threads)
- **check mem**: Doesn't just report memory - it runs a continuous allocation loop with real-time safety monitoring that stops when memory diagnostic is off, allocation fails, or system becomes unstable
- **check disk**: Doesn't call chkdsk - it directly queries volume information, reads disk geometry, and performs actual I/O benchmarking

(END OF AI USAGE)
## Compilation

### Using MinGW (Recommended)

```bash
gcc -o checks.exe checks.c -luser32 -lpsapi -Wall -O2
```

### Using MSVC (Visual Studio)

```bash
cl checks.c /Fe:checks.exe user32.lib psapi.lib
```

## Usage

Run the compiled executable:

```bash
checks.exe
```

### Available Commands

| Command | Description |
|---------|-------------|
| `help` | Display help screen with all commands |
| `version` | Show version number |
| `clear` | Clear the screen |
| `check exec <filename>` | Load executable under debugger and monitor execution |
| `check log` | Display the activity log |
| `check inpath <cmd>` | Verify if a command exists in PATH |
| `check disk [drive]` | Analyze disk (default: C:\\, can specify E:\\ or E:) |
| `check mem` | Run memory allocation loop with safety protocol |
| `exit` | Exit the program and save log |

### Keyboard Shortcuts

- **Ctrl+C** - Emergency failsafe (stops all checks immediately)
- **Ctrl+E** - Quick exit with log save

## Detailed Examples

### Check Executable (Debugger Mode)

```
>>> check exec C:\Windows\System32\notepad.exe
[CHECK EXEC] Loading executable: C:\Windows\System32\notepad.exe
[PE HEADER] DOS Header at 0x0000000000000000
[PE HEADER] PE Signature offset: 0x000000F8
[PE HEADER] Valid PE signature found
[COFF HEADER] Machine type: 0x8664
[COFF HEADER] Number of sections: 6
[COFF HEADER] Timestamp: 1625680234
[COFF HEADER] Characteristics: 0x0022

[DEBUGGER] Creating process under checks debugger...
[DEBUGGER] Process created, PID: 12345
[DEBUGGER] Thread ID: 67890
[DEBUGGER] Process handle: 0x0000000000000123
[DEBUGGER] Monitoring execution...

[EVENT 1] CREATE_PROCESS
  Base address: 0x00007FF6A2B00000
  Entry point: 0x00007FF6A2B01234
[EVENT 2] LOAD_DLL
  Base address: 0x00007FF8B3C00000
[EVENT 3] EXCEPTION: 0x80000003
  Address: 0x00007FF8B3C12345
  Type: Breakpoint
...
```

### Check Memory (Stress Test)

```
>>> check mem
[CHECK MEM] Starting memory diagnostic with safety protocol
[MEM START] Working set: 5.23 MB
[MEM START] Starting allocation loop...
[PROTOCOL] Safety monitoring active
[PROTOCOL] Will stop on: memory diagnostic off, allocation failure, or system instability

[ITERATION 0000] Allocated: 0x000001A2B3C00000 | Total: 1.00 MB | Working set: 6.45 MB | Peak: 6.45 MB
[ITERATION 0010] Allocated: 0x000001A2B4D00000 | Total: 11.00 MB | Working set: 17.89 MB | Peak: 17.89 MB
[ITERATION 0020] Allocated: 0x000001A2B5E00000 | Total: 21.00 MB | Working set: 28.12 MB | Peak: 28.12 MB
...
[ITERATION 0990] Allocated: 0x000001A2C9F00000 | Total: 991.00 MB | Working set: 1005.34 MB | Peak: 1005.34 MB

[MEM TEST] Completed in 125.43 seconds
[MEM TEST] Total iterations: 1000
[MEM TEST] Total allocated: 1000.00 MB
[MEM TEST] Failures: 0

[CLEANUP] Freeing all allocated memory...
[CLEANUP] Freed 0/1000 allocations
[CLEANUP] Freed 100/1000 allocations
...
[CLEANUP] Final working set: 5.67 MB
[RESULT] Memory diagnostic: PASSED
```

### Check Disk

```
>>> check disk E:\
[CHECK DISK] Analyzing drive: E:\
[DISK INFO] Type: Fixed
[VOLUME] Name: DATA
[VOLUME] Serial: A3B4C5D6
[VOLUME] File system: NTFS
[SPACE] Total: 500.00 GB
[SPACE] Free: 250.00 GB
[SPACE] Used: 250.00 GB (50.0%)
[GEOMETRY] Bytes per sector: 512
[GEOMETRY] Sectors per cluster: 8
[GEOMETRY] Cluster size: 4096 bytes
[GEOMETRY] Total clusters: 131072000
[GEOMETRY] Free clusters: 65536000

[IO TEST] Starting disk read/write test...
[IO TEST] Write: 245.67 MB/s (1024 KB in 0.004 sec)
[IO TEST] Read: 387.23 MB/s (1024 KB in 0.003 sec)
[IO TEST] Disk performance: GOOD
```

## How It Works

### check exec (Debugger)
1. Validates PE executable format (MZ signature, PE header, COFF header)
2. Creates process with `DEBUG_PROCESS` flag
3. Enters debug event loop monitoring:
   - Process/thread creation
   - DLL loading
   - Exceptions and breakpoints
   - Debug output strings
4. Reports all events with memory addresses and details
5. Can be stopped with failsafe (Ctrl+C)

### check mem (Memory Stress Test)
1. Allocates tracking structure for up to 1000 allocations
2. Enters loop allocating 1MB blocks
3. Each iteration:
   - Attempts allocation
   - Writes to memory (ensures real allocation)
   - Tracks memory address and working set
   - Checks system memory load
   - Detects potential leaks
4. Safety protocol stops on:
   - Allocation failure
   - System memory > 90%
   - Memory leak detection
   - Failsafe triggered
5. Cleans up all allocations before exit

### check disk (Low-Level Analysis)
1. Queries drive type and volume information
2. Reads disk geometry (sectors, clusters, etc.)
3. Calculates space usage
4. Performs actual I/O benchmark:
   - Creates temporary file
   - Writes 1MB of data
   - Reads it back
   - Measures throughput
5. Reports performance rating

## Log File

All activities are logged to `checks.log`:

```
[2026-02-01 14:23:45] checks started
[2026-02-01 14:24:12] check exec started
[2026-02-01 14:25:45] check exec completed
[2026-02-01 14:26:01] check mem started
[2026-02-01 14:28:15] check mem - PASSED
[2026-02-01 14:29:01] Normal exit
```

## Safety Features

- **Failsafe System**: Ctrl+C immediately stops all checks
- **Memory Protection**: Stops allocation before system crashes
- **Leak Detection**: Monitors for unusual memory patterns
- **System Load Monitoring**: Won't stress system beyond 90% memory
- **Process Isolation**: Debugged processes run in separate console

## Requirements

- Windows 7 or later
- GCC (MinGW) or MSVC compiler
- Administrator privileges recommended (for some disk operations)

## Notes

- The debugger creates processes in a new console window
- Memory test allocates up to 1GB by default (configurable)
- Disk I/O test creates temporary files that auto-delete
- All operations are logged with timestamps
- Commands are case-insensitive

## Configuration

Edit these defines in `checks.c` to customize:

```c
#define MEM_TEST_ITERATIONS 1000    // Number of 1MB allocations
#define MEM_ALLOC_SIZE (1024 * 1024)  // Size per allocation
```

## Version

Current version: **1.0.0**

## License

GPL 2.0
