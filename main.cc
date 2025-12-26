#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <filesystem>
#include <shlwapi.h>
#include <set>
#include <algorithm>
#include <fstream>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// RAII包装器用于Windows句柄
struct HandleGuard
{
    HANDLE handle;
    HandleGuard(HANDLE h) : handle(h) {}
    ~HandleGuard()
    {
        if (handle != INVALID_HANDLE_VALUE && handle != NULL)
            CloseHandle(handle);
    }
    operator HANDLE() const { return handle; }
};

// RAII包装器用于内存映射视图
struct MappedViewGuard
{
    LPVOID address;
    MappedViewGuard(LPVOID addr) : address(addr) {}
    ~MappedViewGuard()
    {
        if (address)
            UnmapViewOfFile(address);
    }
    operator LPVOID() const { return address; }
};

// 将RVA转换为文件偏移量
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (rva >= section[i].VirtualAddress &&
            rva < section[i].VirtualAddress + section[i].Misc.VirtualSize)
        {
            return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }
    }
    return 0; // 未找到
}

// 从延迟加载导入表中提取DLL
std::vector<std::string> GetDelayLoadDLLs(PIMAGE_NT_HEADERS ntHeaders, LPVOID baseAddress, DWORD fileSize)
{
    std::vector<std::string> dllList;

    // 获取延迟加载导入表
    // 注意：延迟加载表的索引通常是 IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (值为 13)
    auto &delayLoadDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delayLoadDir.VirtualAddress == 0 || delayLoadDir.Size == 0)
    {
        std::cout << "Info: File has no delay load import table" << std::endl;
        return dllList;
    }

    std::cout << "Found delay load import table, starting to parse..." << std::endl;

    // 将RVA转换为文件偏移量
    DWORD delayLoadOffset = RvaToFileOffset(ntHeaders, delayLoadDir.VirtualAddress);
    if (delayLoadOffset == 0)
    {
        std::cerr << "Warning: Unable to convert delay load table RVA to file offset" << std::endl;
        return dllList;
    }

    PIMAGE_DELAYLOAD_DESCRIPTOR delayDesc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((BYTE *)baseAddress + delayLoadOffset);
    size_t delayTableSize = delayLoadDir.Size;
    size_t maxDescriptorCount = delayTableSize / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);

    const size_t MAX_DLL_NAME_LEN = 256;
    std::cout << "Starting to scan delay load table, up to " << maxDescriptorCount << " entries..." << std::endl;

    for (size_t i = 0; i < maxDescriptorCount; ++i)
    {
        // 检查描述符是否有效（所有字段都为0表示结束）
        if (delayDesc[i].Attributes.AllAttributes == 0 &&
            delayDesc[i].DllNameRVA == 0 &&
            delayDesc[i].ModuleHandleRVA == 0 &&
            delayDesc[i].ImportAddressTableRVA == 0 &&
            delayDesc[i].ImportNameTableRVA == 0 &&
            delayDesc[i].BoundImportAddressTableRVA == 0 &&
            delayDesc[i].UnloadInformationTableRVA == 0 &&
            delayDesc[i].TimeDateStamp == 0)
        {
            break;
        }

        if (delayDesc[i].DllNameRVA == 0)
        {
            continue;
        }

        // 将DLL名称RVA转换为文件偏移量
        DWORD nameOffset = RvaToFileOffset(ntHeaders, delayDesc[i].DllNameRVA);
        if (nameOffset == 0)
        {
            std::cerr << "Warning: Skipping invalid delay load DLL name RVA: 0x" << std::hex << delayDesc[i].DllNameRVA << std::endl;
            continue;
        }

        const BYTE *dllNameAddr = (BYTE *)baseAddress + nameOffset;
        if (dllNameAddr < (BYTE *)baseAddress || dllNameAddr >= ((BYTE *)baseAddress + fileSize))
        {
            std::cerr << "Warning: Skipping out-of-bounds delay load DLL name address" << std::endl;
            continue;
        }

        // 检查字符串长度和结尾
        size_t len = strnlen((const char *)dllNameAddr, MAX_DLL_NAME_LEN);
        if (len == MAX_DLL_NAME_LEN || dllNameAddr + len >= ((BYTE *)baseAddress + fileSize))
        {
            std::cerr << "Warning: Skipping invalid or out-of-bounds delay load DLL name string" << std::endl;
            continue;
        }

        std::string dllName((const char *)dllNameAddr, len);
        dllList.push_back(dllName);
        std::cout << "Found delay load DLL: " << dllName << std::endl;
    }

    std::cout << "Completed scanning delay load table, found " << dllList.size() << " DLLs" << std::endl;
    return dllList;
}

// 前向声明
std::vector<std::string> ParseFileDependencies(const char *filePath);
bool IsSystemCoreDLL(const std::string &dllName);
bool IsSystemDirectory(const std::string &dllPath);
std::vector<std::string> GetDependentDLLs(const char *executablePath, bool recursive = false, const std::vector<std::string> &extraDirs = {});
std::string FindDLLFile(const std::string &dllName, const std::string &exeDir, const std::vector<std::string> &extraDirs = {});
void GetRecursiveDependentDLLs(const std::string &dllPath, const std::string &exeDir, int depth, const std::vector<std::string> &extraDirs = {});
bool CopyDependentDLLs(const std::vector<std::string> &dllList, const std::string &exePath, const std::string &destDir, const std::vector<std::string> &extraDirs = {}, bool copyAll = false);

// 全局集合，用于跟踪已处理的DLL，避免重复和循环依赖
std::set<std::string> processedDLLs;
std::set<std::string> globalDLLSet;

// 全局变量：最大递归深度
int g_maxRecursionDepth = 20;

// 全局变量：要忽略的 DLL 名称列表
std::set<std::string> g_ignoredDLLNames;
// 全局变量：要忽略的 DLL 文件路径列表
std::set<std::string> g_ignoredDLLPaths;
// 全局变量：要忽略的文件夹路径列表
std::set<std::string> g_ignoredDirectories;

// 递归获取DLL依赖
void GetRecursiveDependentDLLs(const std::string &dllPath, const std::string &exeDir, int depth, const std::vector<std::string> &extraDirs)
{
    if (depth > g_maxRecursionDepth)
    {
        std::cout << std::string(depth * 2, ' ') << "Warning: Maximum recursion depth (" << g_maxRecursionDepth << ") reached, stopping further analysis" << std::endl;
        return;
    }

    std::string dllName = std::filesystem::path(dllPath).filename().string();

    // 检查是否已处理过这个DLL
    if (processedDLLs.find(dllPath) != processedDLLs.end())
    {
        std::cout << std::string(depth * 2, ' ') << "Info: Already processed: " << dllName << std::endl;
        return;
    }

    // 标记为已处理
    processedDLLs.insert(dllPath);
    globalDLLSet.insert(dllName);

    std::cout << std::string(depth * 2, ' ') << "Analyzing: " << dllName << " (depth: " << depth << ")" << std::endl;

    // 获取这个DLL的依赖
    std::vector<std::string> dependencies = ParseFileDependencies(dllPath.c_str());

    // 递归处理每个依赖
    for (const auto &depName : dependencies)
    {
        // 检查是否为系统核心DLL
        if (IsSystemCoreDLL(depName))
        {
            std::cout << std::string((depth + 1) * 2, ' ') << "[System Core DLL] Skipped: " << depName << std::endl;
            // 仍然添加到集合中，但不再递归分析
            globalDLLSet.insert(depName);
            continue;
        }

        // 查找依赖的DLL
        std::string depPath = FindDLLFile(depName, exeDir, extraDirs);
        if (depPath.empty())
        {
            std::cerr << std::string((depth + 1) * 2, ' ') << "Warning: Unable to find: " << depName << std::endl;
            // 即使找不到也添加到集合中
            globalDLLSet.insert(depName);
            continue;
        }

        // 添加到全局集合
        globalDLLSet.insert(depName);

        // 递归分析这个DLL的依赖
        GetRecursiveDependentDLLs(depPath, exeDir, depth + 1, extraDirs);
    }
}

// 内部函数：解析单个文件的依赖（不递归）
std::vector<std::string> ParseFileDependencies(const char *filePath)
{
    std::vector<std::string> dllList;

    std::cout << "Analyzing file: " << filePath << std::endl;

    HandleGuard hFile(CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL));
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error: Unable to open file (Error code: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    HandleGuard hMap(CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL));
    if (!hMap)
    {
        std::cerr << "Error: Unable to create file mapping (Error code: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    MappedViewGuard baseAddress(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!baseAddress)
    {
        std::cerr << "Error: Unable to map file view (Error code: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(LPVOID)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Error: Invalid DOS signature" << std::endl;
        return dllList;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)(LPVOID)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Error: Invalid NT signature" << std::endl;
        return dllList;
    }

    // 检查PE文件架构
    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::cerr << "Warning: Unsupported PE file architecture: 0x" << std::hex << ntHeaders->FileHeader.Machine << std::endl;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        std::cerr << "Error: Unable to get file size" << std::endl;
        return dllList;
    }

    // 使用set来去重
    std::set<std::string> dllSet;

    // 处理常规导入表
    auto &importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0 && importDir.Size != 0)
    {
        std::cout << "\n=== Parsing Regular Import Table ===" << std::endl;

        // 将RVA转换为文件偏移量
        DWORD importDirOffset = RvaToFileOffset(ntHeaders, importDir.VirtualAddress);
        if (importDirOffset == 0)
        {
            std::cerr << "Error: Unable to convert import table RVA to file offset" << std::endl;
            return dllList;
        }

        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)(LPVOID)baseAddress + importDirOffset);
        size_t importTableSize = importDir.Size;
        size_t maxDescriptorCount = importTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);

        const size_t MAX_DLL_NAME_LEN = 256;
        std::cout << "Starting to scan import table, up to " << maxDescriptorCount << " entries..." << std::endl;

        for (size_t i = 0; i < maxDescriptorCount; ++i)
        {
            if (importDescriptor[i].Name == 0)
                break;

            // 将DLL名称RVA转换为文件偏移量
            DWORD nameOffset = RvaToFileOffset(ntHeaders, importDescriptor[i].Name);
            if (nameOffset == 0)
            {
                std::cerr << "Warning: Skipping invalid DLL name RVA: 0x" << std::hex << importDescriptor[i].Name << std::endl;
                continue;
            }

            const BYTE *dllNameAddr = (BYTE *)(LPVOID)baseAddress + nameOffset;
            if (dllNameAddr < (BYTE *)(LPVOID)baseAddress || dllNameAddr >= ((BYTE *)(LPVOID)baseAddress + fileSize))
            {
                std::cerr << "Warning: Skipping out-of-bounds DLL name address" << std::endl;
                continue;
            }

            // 检查字符串长度和结尾
            size_t len = strnlen((const char *)dllNameAddr, MAX_DLL_NAME_LEN);
            if (len == MAX_DLL_NAME_LEN || dllNameAddr + len >= ((BYTE *)(LPVOID)baseAddress + fileSize))
            {
                std::cerr << "Warning: Skipping invalid or out-of-bounds DLL name string" << std::endl;
                continue;
            }

            std::string dllName((const char *)dllNameAddr, len);
            dllSet.insert(dllName);
            std::cout << "Found DLL: " << dllName << std::endl;
        }

        std::cout << "Completed scanning regular import table, found " << dllSet.size() << " dependent DLLs" << std::endl;
    }
    else
    {
        std::cout << "Info: File has no regular import table" << std::endl;
    }

    // 处理延迟加载导入表
    std::cout << "\n=== Parsing Delay Load Import Table ===" << std::endl;
    auto delayLoadDLLs = GetDelayLoadDLLs(ntHeaders, (LPVOID)baseAddress, fileSize);
    for (const auto &dll : delayLoadDLLs)
    {
        dllSet.insert(dll);
    }

    // 将set转换为vector
    dllList.assign(dllSet.begin(), dllSet.end());

    std::cout << "\nTotal found " << dllList.size() << " dependent DLL(s) (after deduplication)" << std::endl;
    return dllList;
}

// 公共接口：获取依赖DLL（支持递归）
std::vector<std::string> GetDependentDLLs(const char *executablePath, bool recursive, const std::vector<std::string> &extraDirs)
{
    if (recursive)
    {
        // 清空全局集合
        processedDLLs.clear();
        globalDLLSet.clear();

        std::cout << "\n=== Starting Recursive Dependency Analysis ===" << std::endl;

        std::string exeDir = std::filesystem::path(executablePath).parent_path().string();

        // 开始递归分析
        GetRecursiveDependentDLLs(executablePath, exeDir, 0, extraDirs);

        std::cout << "\n=== Recursive Analysis Complete ===" << std::endl;
        std::cout << "Total " << globalDLLSet.size() << " unique DLL(s) found (including all levels)" << std::endl;

        // 转换为vector
        return std::vector<std::string>(globalDLLSet.begin(), globalDLLSet.end());
    }
    else
    {
        // 非递归模式，只分析第一层
        return ParseFileDependencies(executablePath);
    }
}

// 获取系统目录路径
std::string GetSystemDirectory()
{
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    return std::string(systemDir);
}

// 获取Windows目录路径
std::string GetWindowsDirectory()
{
    char windowsDir[MAX_PATH];
    GetWindowsDirectoryA(windowsDir, MAX_PATH);
    return std::string(windowsDir);
}

// 系统核心DLL列表
// 注意：C++ 运行库 (MSVCR*.dll, MSVCP*.dll, UCRTBASE.dll, VCRUNTIME*.dll, VCCORLIB*.dll)
// 不在此列表中，需要被复制
const std::set<std::string> systemCoreDLLs = {
    "KERNEL32.dll",
    "KERNEL32.DLL",
    "USER32.dll",
    "USER32.DLL",
    "GDI32.dll",
    "GDI32.DLL",
    "ADVAPI32.dll",
    "ADVAPI32.DLL",
    "SHELL32.dll",
    "SHELL32.DLL",
    "COMCTL32.dll",
    "COMCTL32.DLL",
    "COMDLG32.dll",
    "COMDLG32.DLL",
    "OLE32.dll",
    "OLE32.DLL",
    "OLEAUT32.dll",
    "OLEAUT32.DLL",
    "WS2_32.dll",
    "WS2_32.DLL",
    "WINSPOOL.DRV",
    "WINSPOOL.drv",
    "VERSION.dll",
    "VERSION.DLL",
    "IMM32.dll",
    "IMM32.DLL",
    "NTDLL.dll",
    "NTDLL.DLL",
    "CRYPT32.dll",
    "CRYPT32.DLL",
    "RPCRT4.dll",
    "RPCRT4.DLL",
    "SHLWAPI.dll",
    "SHLWAPI.DLL"};

// 判断DLL是否为系统核心DLL
bool IsSystemCoreDLL(const std::string &dllName)
{
    // 转换为大写进行比较
    std::string upperDllName = dllName;
    std::transform(upperDllName.begin(), upperDllName.end(), upperDllName.begin(), ::toupper);

    // 1. 检查是否为 API Sets 虚拟库
    // API Sets 是虚拟 DLL，以 api-ms-win- 或 ext-ms- 开头
    if (upperDllName.find("API-MS-WIN-") == 0 || upperDllName.find("EXT-MS-") == 0)
    {
        return true;
    }

    // 2. 检查是否在系统核心DLL列表中
    for (const auto &systemDll : systemCoreDLLs)
    {
        std::string upperSystemDll = systemDll;
        std::transform(upperSystemDll.begin(), upperSystemDll.end(), upperSystemDll.begin(), ::toupper);
        if (upperDllName == upperSystemDll)
        {
            return true;
        }
    }

    return false;
}

// 检查是否为 C++ 运行库 DLL
bool IsCppRuntimeDLL(const std::string &dllName)
{
    // 转换为大写进行比较
    std::string upperDllName = dllName;
    std::transform(upperDllName.begin(), upperDllName.end(), upperDllName.begin(), ::toupper);

    // 检查是否为 C 运行库 (MSVCR*.dll, VCRUNTIME*.dll)
    if (upperDllName.find("MSVCR") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4)
    {
        return true;
    }
    if (upperDllName.find("VCRUNTIME") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4)
    {
        return true;
    }

    // 检查是否为 C++ 标准库 (MSVCP*.dll)
    if (upperDllName.find("MSVCP") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4)
    {
        return true;
    }

    // 检查是否为 C++/CX 库 (VCCORLIB*.dll)
    if (upperDllName.find("VCCORLIB") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4)
    {
        return true;
    }

    // 检查是否为 Universal C Runtime (UCRTBASE.dll)
    if (upperDllName == "UCRTBASE.DLL")
    {
        return true;
    }

    // 检查是否为 ConcRT 库 (CONCRT*.dll)
    if (upperDllName.find("CONCRT") == 0 && upperDllName.find(".DLL") == upperDllName.length() - 4)
    {
        return true;
    }

    return false;
}

// 判断DLL路径是否位于系统核心目录
bool IsSystemDirectory(const std::string &dllPath)
{
    if (dllPath.empty())
    {
        return false;
    }

    // 提取 DLL 文件名
    std::string dllName = std::filesystem::path(dllPath).filename().string();

    // 如果是 C++ 运行库，即使位于系统目录也不跳过
    if (IsCppRuntimeDLL(dllName))
    {
        return false;
    }

    // 转换为大写进行路径比较
    std::string upperPath = dllPath;
    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::toupper);

    // 获取系统核心目录路径
    std::string systemDir = GetSystemDirectory();
    std::string windowsDir = GetWindowsDirectory();

    std::transform(systemDir.begin(), systemDir.end(), systemDir.begin(), ::toupper);
    std::transform(windowsDir.begin(), windowsDir.end(), windowsDir.begin(), ::toupper);

    // 检查是否在 System32 目录中
    if (upperPath.find(systemDir) == 0)
    {
        // 确保后面是路径分隔符或者是完全匹配
        size_t systemDirLen = systemDir.length();
        if (upperPath.length() == systemDirLen ||
            upperPath[systemDirLen] == '\\' ||
            upperPath[systemDirLen] == '/')
        {
            return true;
        }
    }

    // 检查是否在 Windows 目录下（包括 SysWOW64, WinSxS 等）
    if (upperPath.find(windowsDir) == 0)
    {
        // 检查是否为系统核心子目录
        size_t windowsDirLen = windowsDir.length();
        if (upperPath.length() > windowsDirLen &&
            (upperPath[windowsDirLen] == '\\' || upperPath[windowsDirLen] == '/'))
        {
            // 获取 Windows 目录下的子路径
            std::string subPath = upperPath.substr(windowsDirLen + 1);

            // 检查是否为系统核心子目录
            const std::vector<std::string> systemSubDirs = {
                "SYSTEM32",
                "SYSWOW64",
                "WINSXS",
                "GLOBALIZATION"
            };

            for (const auto &subDir : systemSubDirs)
            {
                if (subPath.find(subDir) == 0)
                {
                    // 确保后面是路径分隔符或者是完全匹配
                    if (subPath.length() == subDir.length() ||
                        subPath[subDir.length()] == '\\' ||
                        subPath[subDir.length()] == '/')
                    {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

// 获取环境变量PATH中的目录列表
std::vector<std::string> GetPathDirectories()
{
    std::vector<std::string> pathDirs;
    char *pathEnv;
    size_t len;
    _dupenv_s(&pathEnv, &len, "PATH");

    if (pathEnv)
    {
        char *context = nullptr;
        char *token = strtok_s(pathEnv, ";", &context);
        while (token != nullptr)
        {
            pathDirs.push_back(std::string(token));
            token = strtok_s(nullptr, ";", &context);
        }
        free(pathEnv);
    }

    return pathDirs;
}

// 从文件中读取额外的搜索目录
std::vector<std::string> LoadExtraSearchDirectories(const std::string &filePath)
{
    std::vector<std::string> directories;
    std::ifstream file(filePath);

    if (!file.is_open())
    {
        std::cerr << "Warning: Unable to open extra search directories file: " << filePath << std::endl;
        return directories;
    }

    std::cout << "Loading extra search directories from: " << filePath << std::endl;

    std::string line;
    int lineNum = 0;
    while (std::getline(file, line))
    {
        lineNum++;

        // 跳过空行
        if (line.empty())
        {
            continue;
        }

        // 跳过注释行（以#或;开头）
        if (line[0] == '#' || line[0] == ';')
        {
            continue;
        }

        // 去除行首尾的空白字符
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // 再次检查是否为空
        if (line.empty())
        {
            continue;
        }

        // 检查目录是否存在
        if (!PathFileExistsA(line.c_str()))
        {
            std::cerr << "Warning (line " << lineNum << "): Directory does not exist, skipping: " << line << std::endl;
            continue;
        }

        directories.push_back(line);
        std::cout << "  Added: " << line << std::endl;
    }

    file.close();

    std::cout << "Loaded " << directories.size() << " extra search director" << (directories.size() == 1 ? "y" : "ies") << std::endl;

    return directories;
}

// 从文件中读取要忽略的 DLL 列表
void LoadIgnoredDLLs(const std::string &filePath)
{
    std::ifstream file(filePath);

    if (!file.is_open())
    {
        std::cerr << "Warning: Unable to open ignore DLL file: " << filePath << std::endl;
        return;
    }

    std::cout << "Loading ignore list from: " << filePath << std::endl;

    std::string line;
    int lineNum = 0;
    int nameCount = 0, pathCount = 0, dirCount = 0;

    while (std::getline(file, line))
    {
        lineNum++;

        // 跳过空行
        if (line.empty())
        {
            continue;
        }

        // 跳过注释行（以#或;开头）
        if (line[0] == '#' || line[0] == ';')
        {
            continue;
        }

        // 去除行首尾的空白字符
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // 再次检查是否为空
        if (line.empty())
        {
            continue;
        }

        // 检查是否为文件路径（包含 .dll 或 .DLL）
        if (line.find(".dll") != std::string::npos || line.find(".DLL") != std::string::npos)
        {
            // 检查是否为存在的文件
            DWORD attrs = GetFileAttributesA(line.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES)
            {
                if (attrs & FILE_ATTRIBUTE_DIRECTORY)
                {
                    // 是目录
                    g_ignoredDirectories.insert(line);
                    dirCount++;
                    std::cout << "  Added directory to ignore: " << line << std::endl;
                }
                else
                {
                    // 是文件
                    g_ignoredDLLPaths.insert(line);
                    pathCount++;
                    std::cout << "  Added DLL path to ignore: " << line << std::endl;
                }
            }
            else
            {
                // 文件不存在,可能只是 DLL 名称
                g_ignoredDLLNames.insert(line);
                nameCount++;
                std::cout << "  Added DLL name to ignore: " << line << std::endl;
            }
        }
        else
        {
            // 可能是目录路径(不包含 .dll)
            DWORD attrs = GetFileAttributesA(line.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
            {
                g_ignoredDirectories.insert(line);
                dirCount++;
                std::cout << "  Added directory to ignore: " << line << std::endl;
            }
            else
            {
                // 当作 DLL 名称处理
                g_ignoredDLLNames.insert(line);
                nameCount++;
                std::cout << "  Added DLL name to ignore: " << line << std::endl;
            }
        }
    }

    file.close();

    std::cout << "Loaded " << nameCount << " DLL names, " << pathCount << " DLL paths, and " << dirCount << " director" << (dirCount == 1 ? "y" : "ies") << " to ignore" << std::endl;
}

// 检查 DLL 是否应该被忽略
bool ShouldIgnoreDLL(const std::string &dllName, const std::string &dllPath)
{
    // 检查 DLL 名称
    for (const auto &ignoredName : g_ignoredDLLNames)
    {
        // 不区分大小写比较
        std::string upperDllName = dllName;
        std::string upperIgnoredName = ignoredName;
        std::transform(upperDllName.begin(), upperDllName.end(), upperDllName.begin(), ::toupper);
        std::transform(upperIgnoredName.begin(), upperIgnoredName.end(), upperIgnoredName.begin(), ::toupper);

        if (upperDllName == upperIgnoredName)
        {
            return true;
        }
    }

    // 检查 DLL 文件路径
    for (const auto &ignoredPath : g_ignoredDLLPaths)
    {
        // 不区分大小写比较路径
        if (_stricmp(dllPath.c_str(), ignoredPath.c_str()) == 0)
        {
            return true;
        }
    }

    // 检查是否在忽略的目录中
    for (const auto &ignoredDir : g_ignoredDirectories)
    {
        // 检查 DLL 路径是否以忽略目录开头(不区分大小写)
        size_t dirLen = ignoredDir.length();
        if (dllPath.length() >= dirLen)
        {
            std::string dllPathPrefix = dllPath.substr(0, dirLen);
            if (_stricmp(dllPathPrefix.c_str(), ignoredDir.c_str()) == 0)
            {
                // 确保后面是路径分隔符
                if (dllPath.length() == dirLen || dllPath[dirLen] == '\\' || dllPath[dirLen] == '/')
                {
                    return true;
                }
            }
        }
    }

    return false;
}

// 搜索DLL文件
std::string FindDLLFile(const std::string &dllName, const std::string &exeDir, const std::vector<std::string> &extraDirs)
{
    // 首先在额外指定的目录中查找（最高优先级）
    for (const auto &dir : extraDirs)
    {
        std::string dllPath = dir + "\\" + dllName;
        if (PathFileExistsA(dllPath.c_str()))
        {
            return dllPath;
        }
    }

    // 在可执行文件目录中查找
    std::string dllPath = exeDir + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str()))
    {
        return dllPath;
    }

    // 在当前工作目录中查找
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    dllPath = std::string(currentDir) + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str()))
    {
        return dllPath;
    }

    // 在系统目录中查找
    dllPath = GetSystemDirectory() + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str()))
    {
        return dllPath;
    }

    // 在Windows目录中查找
    dllPath = GetWindowsDirectory() + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str()))
    {
        return dllPath;
    }

    // 在PATH环境变量指定的目录中查找
    auto pathDirs = GetPathDirectories();
    for (const auto &dir : pathDirs)
    {
        dllPath = dir + "\\" + dllName;
        if (PathFileExistsA(dllPath.c_str()))
        {
            return dllPath;
        }
    }

    return ""; // 未找到
}

// 复制文件
bool CopyFileToDirectory(const std::string &sourcePath, const std::string &destDir)
{
    if (sourcePath.empty() || destDir.empty())
    {
        return false;
    }

    // 确保目标目录存在
    if (!CreateDirectoryA(destDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        std::cerr << "Error: Unable to create target directory " << destDir << " (Error code: " << GetLastError() << ")" << std::endl;
        return false;
    }

    // 构造目标文件路径
    std::string fileName = std::filesystem::path(sourcePath).filename().string();
    std::string destPath = destDir + "\\" + fileName;

    // 检查目标文件是否已存在
    if (PathFileExistsA(destPath.c_str()))
    {
        std::cout << "Warning: File already exists, skipping copy: " << fileName << std::endl;
        return true;
    }

    // 复制文件
    if (CopyFileA(sourcePath.c_str(), destPath.c_str(), FALSE))
    {
        std::cout << "Successfully copied: " << fileName << std::endl;
        return true;
    }
    else
    {
        std::cerr << "Error: Unable to copy file " << fileName << " (Error code: " << GetLastError() << ")" << std::endl;
        return false;
    }
}

// 复制所有依赖的DLL
bool CopyDependentDLLs(const std::vector<std::string> &dllList, const std::string &exePath, const std::string &destDir, const std::vector<std::string> &extraDirs, bool copyAll)
{
    if (dllList.empty())
    {
        std::cout << "No DLL files to copy" << std::endl;
        return true;
    }

    // 获取可执行文件所在目录
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();

    std::cout << "\nStarting to copy DLL files to target directory: " << destDir << std::endl;
    if (copyAll)
    {
        std::cout << "Note: --copy-all flag is set, system core DLLs will NOT be skipped" << std::endl;
    }
    else
    {
        std::cout << "Note: System core DLLs (such as KERNEL32.dll, etc.) will be automatically skipped as these are Windows built-in DLLs" << std::endl;
    }

    if (!g_ignoredDLLNames.empty() || !g_ignoredDLLPaths.empty() || !g_ignoredDirectories.empty())
    {
        std::cout << "Note: " << (g_ignoredDLLNames.size() + g_ignoredDLLPaths.size() + g_ignoredDirectories.size()) << " item(s) in ignore list" << std::endl;
    }

    int successCount = 0;
    int failCount = 0;
    int skippedCount = 0;
    int ignoredCount = 0;

    for (const auto &dllName : dllList)
    {
        std::cout << "Searching for: " << dllName << std::endl;

        // 检查是否为系统核心DLL
        if (!copyAll && IsSystemCoreDLL(dllName))
        {
            std::cout << "[System Core DLL] Skipped: " << dllName << " (This is a Windows built-in DLL, no need to copy)" << std::endl;
            skippedCount++;
            continue;
        }

        std::string dllPath = FindDLLFile(dllName, exeDir, extraDirs);
        if (dllPath.empty())
        {
            std::cerr << "Error: Unable to find DLL file: " << dllName << std::endl;
            failCount++;
            continue;
        }

        // 检查 DLL 路径是否位于系统核心目录
        if (!copyAll && IsSystemDirectory(dllPath))
        {
            std::cout << "[System Directory] Skipped: " << dllName << " (Location: " << dllPath << ")" << std::endl;
            std::cout << "  This DLL is in a Windows system directory and will be available on the target system" << std::endl;
            skippedCount++;
            continue;
        }

        // 检查是否在忽略列表中
        if (ShouldIgnoreDLL(dllName, dllPath))
        {
            std::cout << "[Ignored] Skipped: " << dllName << " (in ignore list)" << std::endl;
            ignoredCount++;
            continue;
        }

        std::cout << "Found DLL: " << dllPath << std::endl;

        if (CopyFileToDirectory(dllPath, destDir))
        {
            successCount++;
        }
        else
        {
            failCount++;
        }
    }

    std::cout << "\nCopy completed: " << successCount << " succeeded, " << failCount << " failed, " << skippedCount << " system core DLLs skipped, " << ignoredCount << " ignored by user" << std::endl;
    return failCount == 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 10)
    {
        std::cout << "Usage: " << argv[0] << " <executable_path> [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --release [depth]     Release mode: recursively analyze dependencies (default depth: 2)" << std::endl;
        std::cout << "                         and copy DLLs to the executable's directory" << std::endl;
        std::cout << "  --recursive [depth]   Recursively analyze all DLL dependencies (default depth: 20)" << std::endl;
        std::cout << "  --copy <target_dir>   Copy dependent DLLs to specified directory" << std::endl;
        std::cout << "  --copy-exe-dir        Copy dependent DLLs to the executable's directory" << std::endl;
        std::cout << "  --copy-all            Copy all DLLs including system core DLLs" << std::endl;
        std::cout << "  --search-dirs <file>  Load additional search directories from file (one directory per line)" << std::endl;
        std::cout << "  --ignore-dll <file>   Load ignore list from file (DLL names, paths, or directories)" << std::endl;
        std::cout << "\nExamples:" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release 3" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive 10" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive --copy C:\\DestDir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir --copy-all" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --search-dirs test_path.txt" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release --ignore-dll ignore.txt" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release --search-dirs test_path.txt --ignore-dll ignore.txt" << std::endl;
        std::cout << "\nNote: When using --recursive with --copy, all dependencies at all levels will be copied." << std::endl;
        std::cout << "      By default, system core DLLs will be skipped during copy." << std::endl;
        std::cout << "      Use --copy-all to include system core DLLs." << std::endl;
        std::cout << "      The --search-dirs file should contain one directory path per line." << std::endl;
        std::cout << "      Lines starting with # or ; are treated as comments and ignored." << std::endl;
        std::cout << "      The --ignore-dll file can contain DLL names, DLL paths, or directory paths." << std::endl;
        std::cout << "      --release mode is equivalent to --recursive 2 --copy-exe-dir" << std::endl;
        return 1;
    }

    auto exe_path = argv[1];
    bool copyMode = false;
    bool recursiveMode = false;
    bool releaseMode = false;
    bool copyAllMode = false;
    std::string destDir;
    std::string searchDirsFile;
    std::string ignoreDllFile;
    std::vector<std::string> extraSearchDirs;

    // 解析命令行参数
    int argIndex = 2;
    while (argIndex < argc)
    {
        if (strcmp(argv[argIndex], "--release") == 0)
        {
            releaseMode = true;
            recursiveMode = true;
            copyMode = true;
            // 获取可执行文件所在目录作为目标目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
            argIndex++;

            // 检查是否指定了递归深度
            if (argIndex < argc && argv[argIndex][0] != '-')
            {
                // 尝试解析为数字
                try
                {
                    int depth = std::stoi(argv[argIndex]);
                    if (depth <= 0)
                    {
                        std::cerr << "Error: Recursion depth must be a positive number, got: " << depth << std::endl;
                        return 1;
                    }
                    g_maxRecursionDepth = depth;
                    std::cout << "Info: Release mode: Maximum recursion depth set to: " << g_maxRecursionDepth << std::endl;
                    argIndex++;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: Invalid recursion depth value: " << argv[argIndex] << std::endl;
                    return 1;
                }
            }
            else
            {
                // 使用默认值 2
                g_maxRecursionDepth = 2;
                std::cout << "Info: Release mode: Maximum recursion depth set to: " << g_maxRecursionDepth << " (default)" << std::endl;
            }
        }
        else if (strcmp(argv[argIndex], "--recursive") == 0)
        {
            recursiveMode = true;
            argIndex++;

            // 检查是否指定了递归深度
            if (argIndex < argc && argv[argIndex][0] != '-')
            {
                // 尝试解析为数字
                try
                {
                    int depth = std::stoi(argv[argIndex]);
                    if (depth <= 0)
                    {
                        std::cerr << "Error: Recursion depth must be a positive number, got: " << depth << std::endl;
                        return 1;
                    }
                    g_maxRecursionDepth = depth;
                    std::cout << "Info: Maximum recursion depth set to: " << g_maxRecursionDepth << std::endl;
                    argIndex++;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: Invalid recursion depth value: " << argv[argIndex] << std::endl;
                    return 1;
                }
            }
            else
            {
                // 使用默认值 20
                g_maxRecursionDepth = 20;
            }
        }
        else if (strcmp(argv[argIndex], "--copy") == 0 && argIndex + 1 < argc)
        {
            copyMode = true;
            destDir = argv[argIndex + 1];
            argIndex += 2;
        }
        else if (strcmp(argv[argIndex], "--copy-exe-dir") == 0)
        {
            copyMode = true;
            // 获取可执行文件所在目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "--copy-all") == 0)
        {
            copyAllMode = true;
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "--search-dirs") == 0 && argIndex + 1 < argc)
        {
            searchDirsFile = argv[argIndex + 1];
            extraSearchDirs = LoadExtraSearchDirectories(searchDirsFile);
            if (extraSearchDirs.empty())
            {
                std::cout << "Warning: No extra search directories loaded from: " << searchDirsFile << std::endl;
            }
            argIndex += 2;
        }
        else if (strcmp(argv[argIndex], "--ignore-dll") == 0 && argIndex + 1 < argc)
        {
            ignoreDllFile = argv[argIndex + 1];
            LoadIgnoredDLLs(ignoreDllFile);
            argIndex += 2;
        }
        else
        {
            std::cerr << "Error: Invalid command line argument: " << argv[argIndex] << std::endl;
            return 1;
        }
    }

    auto dlls = GetDependentDLLs(exe_path, recursiveMode, extraSearchDirs);

    std::cout << "\n=== Dependent DLL List ===" << std::endl;
    for (const auto &dll : dlls)
    {
        std::cout << dll << std::endl;
    }
    std::cout << "Total: " << dlls.size() << " DLL(s)" << std::endl;

    // 如果启用了复制模式，则复制DLL文件
    if (copyMode)
    {
        std::cout << "\n=== Starting to Copy DLL Files ===" << std::endl;
        if (CopyDependentDLLs(dlls, exe_path, destDir, extraSearchDirs, copyAllMode))
        {
            std::cout << "All DLL files copied successfully!" << std::endl;
        }
        else
        {
            std::cout << "Some DLL files failed to copy, please check error messages" << std::endl;
            return 1;
        }
    }

    return 0;
}