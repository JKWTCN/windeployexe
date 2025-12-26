# WinDeploy - Windows DLL Dependency Analysis and Deployment Tool

[**中文**](README_CN.md) | **English**

## Introduction

WinDeploy is a command-line tool for analyzing the DLL dependencies of Windows executable files (.exe) and dynamic-link libraries (.dll), with an option to copy these dependent DLL files to a specified directory. This tool is particularly useful for Windows application deployment and distribution, helping developers collect all necessary dependencies.

## Features

- Analyze PE headers of Windows executables and DLLs to extract lists of dependent DLLs
- Support recursive analysis of DLL dependencies at all levels
- Support searching for DLL files in multiple locations (executable directory, system directories, PATH environment variable, etc.)
- Support loading additional search directories and ignore lists from files
- Option to copy dependent DLLs to a specified directory
- Automatically identify and skip Windows core DLLs (such as KERNEL32.dll, USER32.dll, etc.)
- Support both x64 and x86 architecture PE files
- Use RAII pattern for Windows resource management, ensuring proper resource cleanup
- Detailed error handling and log output

## Build Requirements

- Windows operating system
- CMake 3.10 or higher
- C++17 compatible compiler (Visual Studio 2017 or higher recommended)
- Ninja build system (optional)

## Build Instructions

### Using Visual Studio

1. Open Visual Studio
2. Select "Open Local Folder" and choose the project root directory
3. Visual Studio will automatically detect CMakeLists.txt and configure the project
4. Select build configuration (Debug or Release)
5. Click "Build" -> "Build Solution"

### Using Command Line

```bash
# Create build directory
mkdir build
cd build

# Configure project
cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release

# Build project
cmake --build .
```

After building, the executable will be located in the `build/bin` directory.

## Usage

### Basic Usage

```bash
# Analyze executable file's dependent DLLs (first level only)
win_deploy.exe C:\Path\To\YourApp.exe

# Analyze DLL file's dependencies
win_deploy.exe C:\Path\To\YourLibrary.dll

# Recursively analyze all levels of dependent DLLs
win_deploy.exe C:\Path\To\YourApp.exe --recursive

# Recursively analyze with specified maximum depth (default 20)
win_deploy.exe C:\Path\To\YourApp.exe --recursive 10
```

### Release Mode

```bash
# Release mode: recursively analyze dependencies (depth 2) and copy to executable directory
win_deploy.exe C:\Path\To\YourApp.exe --release

# Release mode with specified recursion depth
win_deploy.exe C:\Path\To\YourApp.exe --release 3
```

### Copying Dependent DLLs

```bash
# Copy dependent DLLs to specified directory
win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir

# Copy dependent DLLs to executable file's directory
win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir

# Copy all DLLs (including system core DLLs)
win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir --copy-all
```

### Using Additional Search Directories

```bash
# Load additional search directories from file
win_deploy.exe C:\Path\To\YourApp.exe --search-dirs search_paths.txt

# search_paths.txt file format (one directory path per line):
# C:\MyLibs\bin
# D:\ThirdParty\libs
# # Lines starting with # or ; are treated as comments
```

### Using Ignore Lists

```bash
# Load ignore list from file
win_deploy.exe C:\Path\To\YourApp.exe --ignore-dll ignore.txt

# ignore.txt file format:
# # Can contain DLL names
# unwanted.dll
# # Can contain full paths
# C:\Windows\System32\skip_this.dll
# # Can contain directory paths (all DLLs in that directory will be ignored)
# C:\TemporaryLibs
```

### Combining Options

```bash
# Release mode + additional search directories + ignore list
win_deploy.exe C:\Path\To\YourApp.exe --release --search-dirs search_paths.txt --ignore-dll ignore.txt
```

### Command Line Parameters

```
Usage: win_deploy.exe <executable_path|dll_path> [options]

Options:
  --release [depth]     Release mode: recursively analyze dependencies (default depth: 2) and copy to file's directory
  --recursive [depth]   Recursively analyze all DLL dependencies (default depth: 20)
  --copy <dest_dir>     Copy dependent DLLs to specified directory
  --copy-exe-dir        Copy dependent DLLs to the file's directory
  --copy-all            Copy all DLLs (including system core DLLs)
  --search-dirs <file>  Load additional search directories from file (one path per line)
  --ignore-dll <file>   Load ignore list from file (DLL names, paths, or directories)

Examples:
  win_deploy.exe C:\Path\To\YourApp.exe
  win_deploy.exe C:\Path\To\YourLibrary.dll
  win_deploy.exe C:\Path\To\YourApp.exe --release
  win_deploy.exe C:\Path\To\YourApp.exe --release 3
  win_deploy.exe C:\Path\To\YourApp.exe --recursive
  win_deploy.exe C:\Path\To\YourApp.exe --recursive 10
  win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir
  win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir
  win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir --copy-all
  win_deploy.exe C:\Path\To\YourApp.exe --search-dirs test_path.txt
  win_deploy.exe C:\Path\To\YourApp.exe --release --ignore-dll ignore.txt
  win_deploy.exe C:\Path\To\YourApp.exe --release --search-dirs test_path.txt --ignore-dll ignore.txt
```

**Notes**:

- By default, system core DLLs (such as KERNEL32.dll, USER32.dll, etc.) are automatically skipped during copying
- Use the `--copy-all` parameter to copy all DLLs, including system core DLLs
- `--release` mode is equivalent to `--recursive 2 --copy-exe-dir`

## How It Works

1. **PE File Analysis**: The tool reads the PE header of the executable or DLL, parsing the Import Directory and Delay Import Directory to obtain all dependent DLL names.
2. **Recursive Analysis**: If recursive mode is enabled, the tool analyzes the dependencies of each dependent DLL level by level until the maximum recursion depth is reached or all dependencies are analyzed.
3. **DLL Search**: DLL files are searched in the following priority order:

   - **Additional specified search directories** (specified via `--search-dirs` parameter, highest priority)
   - Directory of the analyzed file
   - Current working directory
   - System directory (System32)
   - Windows directory
   - All directories in PATH environment variable
4. **File Copying**: If copy options are specified, the tool copies found DLL files to the target directory:

   - Automatically identify and skip Windows system core DLLs (unless using `--copy-all`)
   - Skip DLLs in the ignore list
   - Automatically create target directory
   - Skip existing files

## Technical Details

- Use Windows API for file operations and PE file parsing
- Implement RVA (Relative Virtual Address) to file offset conversion
- Support parsing both regular import tables and delay-load import tables
- Use RAII pattern to manage Windows handles and memory-mapped views
- Support detection of multiple PE file architectures (x64, x86)
- Include complete error handling and boundary checks
- Automatically detect system core DLL list, including KERNEL32, USER32, GDI32, ADVAPI32, etc.

## Project Structure

```
windeployexe/
├── main.cc              # Main program source code
├── CMakeLists.txt       # CMake build configuration
├── CMakeSettings.json   # Visual Studio CMake settings
├── .gitignore           # Git ignore file
├── README.MD            # Project documentation (English)
└── README_CN.md         # Project documentation (Chinese)
```

## License

MIT
