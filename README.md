# WinDeploy - Windows Dependency DLL Analysis and Deployment Tool

**[中文](README_CN.MD) | [English](README.MD)**

## Project Introduction

WinDeploy is a command-line tool for analyzing the dependency DLLs of Windows executable files (.exe) and optionally copying these DLL files to a specified directory. This tool is particularly useful for the deployment and distribution of Windows applications, helping developers collect all necessary dependency libraries.

## Features

- Analyze PE headers of Windows executable files to extract the list of dependent DLLs
- Support searching for DLL files in multiple locations (executable directory, system directories, PATH environment variables, etc.)
- Optionally copy dependent DLLs to a specified directory
- Support for x64 and x86 architecture PE files
- Use RAII pattern to manage Windows resources, ensuring proper resource release
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

After building, the executable file will be located in the `build/bin` directory.

## Usage

### Basic Usage

```bash
# Analyze dependency DLLs of an executable
win_deploy.exe C:\Path\To\YourApp.exe
```

### Copy Dependency DLLs to a Specified Directory

```bash
# Copy dependency DLLs to a specified directory
win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir
```

### Copy Dependency DLLs to the Executable's Directory

```bash
# Copy dependency DLLs to the executable's directory
win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir
```

### Command Line Arguments

```
Usage: win_deploy.exe <executable_path> [options]
Options:
  --copy <target_dir>    Copy dependency DLLs to the specified directory
  --copy-exe-dir         Copy dependency DLLs to the executable's directory
Examples:
  win_deploy.exe C:\Path\To\YourApp.exe
  win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir
  win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir
```

## How It Works

1. **PE File Analysis**: The tool reads the PE header of the executable file, parses the Import Directory, and obtains all dependent DLL names.
2. **DLL Search**: Search for DLL files in the following order:

   - Executable file directory
   - Current working directory
   - System directory (System32)
   - Windows directory
   - All directories in the PATH environment variable
3. **File Copying**: If the copy option is specified, the tool will copy the found DLL files to the target directory, automatically create the directory structure, and skip existing files.

## Technical Details

- Use Windows API for file operations and PE file parsing
- Implement RVA (Relative Virtual Address) to file offset conversion
- Use RAII pattern to manage Windows handles and memory-mapped views
- Support detection of various PE file architectures
- Include complete error handling and boundary checks

## Project Structure

```
windeployexe/
├── main.cc              # Main program source code
├── CMakeLists.txt       # CMake build configuration
├── CMakeSettings.json   # Visual Studio CMake settings
├── .gitignore           # Git ignore file
└── README.MD           # Project documentation
```

## License

MIT

## Contributing

Bug reports and feature requests are welcome. If you want to contribute code, please ensure:

1. Code follows the project's coding style
2. Add appropriate comments and documentation
3. Ensure the code compiles and runs correctly on the target platform

## Contact

For questions or suggestions, please contact through:

- Create a GitHub Issue
- Send an email to the project maintainer
