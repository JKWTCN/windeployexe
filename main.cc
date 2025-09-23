#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <filesystem>
#include <shlwapi.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// RAII包装器用于Windows句柄
struct HandleGuard {
    HANDLE handle;
    HandleGuard(HANDLE h) : handle(h) {}
    ~HandleGuard() { if (handle != INVALID_HANDLE_VALUE && handle != NULL) CloseHandle(handle); }
    operator HANDLE() const { return handle; }
};

// RAII包装器用于内存映射视图
struct MappedViewGuard {
    LPVOID address;
    MappedViewGuard(LPVOID addr) : address(addr) {}
    ~MappedViewGuard() { if (address) UnmapViewOfFile(address); }
    operator LPVOID() const { return address; }
};

// 将RVA转换为文件偏移量
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= section[i].VirtualAddress &&
            rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }
    }
    return 0; // 未找到
}

std::vector<std::string> GetDependentDLLs(const char *executablePath)
{
    std::vector<std::string> dllList;

    std::cout << "正在分析文件: " << executablePath << std::endl;

    HandleGuard hFile(CreateFileA(executablePath, GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, 0, NULL));
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "错误: 无法打开文件 (错误代码: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    HandleGuard hMap(CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL));
    if (!hMap)
    {
        std::cerr << "错误: 无法创建文件映射 (错误代码: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    MappedViewGuard baseAddress(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!baseAddress)
    {
        std::cerr << "错误: 无法映射文件视图 (错误代码: " << GetLastError() << ")" << std::endl;
        return dllList;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(LPVOID)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "错误: 无效的DOS签名" << std::endl;
        return dllList;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)(LPVOID)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "错误: 无效的NT签名" << std::endl;
        return dllList;
    }

    // 检查PE文件架构
    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        std::cerr << "警告: 不支持的PE文件架构: 0x" << std::hex << ntHeaders->FileHeader.Machine << std::endl;
    }

    // 获取导入表
    auto& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        std::cout << "信息: 文件没有导入表" << std::endl;
        return dllList;
    }

    // 将RVA转换为文件偏移量
    DWORD importDirOffset = RvaToFileOffset(ntHeaders, importDir.VirtualAddress);
    if (importDirOffset == 0) {
        std::cerr << "错误: 无法转换导入表RVA到文件偏移量" << std::endl;
        return dllList;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)(LPVOID)baseAddress + importDirOffset);
    size_t importTableSize = importDir.Size;
    size_t maxDescriptorCount = importTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        std::cerr << "错误: 无法获取文件大小" << std::endl;
        return dllList;
    }

    const size_t MAX_DLL_NAME_LEN = 256;
    std::cout << "开始扫描导入表，最多 " << maxDescriptorCount << " 个条目..." << std::endl;

    for (size_t i = 0; i < maxDescriptorCount; ++i)
    {
        if (importDescriptor[i].Name == 0)
            break;

        // 将DLL名称RVA转换为文件偏移量
        DWORD nameOffset = RvaToFileOffset(ntHeaders, importDescriptor[i].Name);
        if (nameOffset == 0) {
            std::cerr << "警告: 跳过无效的DLL名称RVA: 0x" << std::hex << importDescriptor[i].Name << std::endl;
            continue;
        }

        const BYTE* dllNameAddr = (BYTE*)(LPVOID)baseAddress + nameOffset;
        if (dllNameAddr < (BYTE*)(LPVOID)baseAddress || dllNameAddr >= ((BYTE*)(LPVOID)baseAddress + fileSize))
        {
            std::cerr << "警告: 跳过越界的DLL名称地址" << std::endl;
            continue;
        }

        // 检查字符串长度和结尾
        size_t len = strnlen((const char*)dllNameAddr, MAX_DLL_NAME_LEN);
        if (len == MAX_DLL_NAME_LEN || dllNameAddr + len >= ((BYTE*)(LPVOID)baseAddress + fileSize))
        {
            std::cerr << "警告: 跳过无效或越界的DLL名称字符串" << std::endl;
            continue;
        }

        std::string dllName((const char*)dllNameAddr, len);
        dllList.push_back(dllName);
        std::cout << "找到DLL: " << dllName << std::endl;
    }

    std::cout << "完成扫描，共找到 " << dllList.size() << " 个依赖DLL" << std::endl;
    return dllList;
}

// 获取系统目录路径
std::string GetSystemDirectory() {
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    return std::string(systemDir);
}

// 获取Windows目录路径
std::string GetWindowsDirectory() {
    char windowsDir[MAX_PATH];
    GetWindowsDirectoryA(windowsDir, MAX_PATH);
    return std::string(windowsDir);
}

// 获取环境变量PATH中的目录列表
std::vector<std::string> GetPathDirectories() {
    std::vector<std::string> pathDirs;
    char* pathEnv;
    size_t len;
    _dupenv_s(&pathEnv, &len, "PATH");
    
    if (pathEnv) {
        char* context = nullptr;
        char* token = strtok_s(pathEnv, ";", &context);
        while (token != nullptr) {
            pathDirs.push_back(std::string(token));
            token = strtok_s(nullptr, ";", &context);
        }
        free(pathEnv);
    }
    
    return pathDirs;
}

// 搜索DLL文件
std::string FindDLLFile(const std::string& dllName, const std::string& exeDir) {
    // 首先在可执行文件目录中查找
    std::string dllPath = exeDir + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str())) {
        return dllPath;
    }
    
    // 在当前工作目录中查找
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    dllPath = std::string(currentDir) + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str())) {
        return dllPath;
    }
    
    // 在系统目录中查找
    dllPath = GetSystemDirectory() + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str())) {
        return dllPath;
    }
    
    // 在Windows目录中查找
    dllPath = GetWindowsDirectory() + "\\" + dllName;
    if (PathFileExistsA(dllPath.c_str())) {
        return dllPath;
    }
    
    // 在PATH环境变量指定的目录中查找
    auto pathDirs = GetPathDirectories();
    for (const auto& dir : pathDirs) {
        dllPath = dir + "\\" + dllName;
        if (PathFileExistsA(dllPath.c_str())) {
            return dllPath;
        }
    }
    
    return ""; // 未找到
}

// 复制文件
bool CopyFileToDirectory(const std::string& sourcePath, const std::string& destDir) {
    if (sourcePath.empty() || destDir.empty()) {
        return false;
    }
    
    // 确保目标目录存在
    if (!CreateDirectoryA(destDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        std::cerr << "错误: 无法创建目标目录 " << destDir << " (错误代码: " << GetLastError() << ")" << std::endl;
        return false;
    }
    
    // 构造目标文件路径
    std::string fileName = std::filesystem::path(sourcePath).filename().string();
    std::string destPath = destDir + "\\" + fileName;
    
    // 检查目标文件是否已存在
    if (PathFileExistsA(destPath.c_str())) {
        std::cout << "警告: 文件已存在，跳过复制: " << fileName << std::endl;
        return true;
    }
    
    // 复制文件
    if (CopyFileA(sourcePath.c_str(), destPath.c_str(), FALSE)) {
        std::cout << "成功复制: " << fileName << std::endl;
        return true;
    } else {
        std::cerr << "错误: 无法复制文件 " << fileName << " (错误代码: " << GetLastError() << ")" << std::endl;
        return false;
    }
}

// 复制所有依赖的DLL
bool CopyDependentDLLs(const std::vector<std::string>& dllList, const std::string& exePath, const std::string& destDir) {
    if (dllList.empty()) {
        std::cout << "没有需要复制的DLL文件" << std::endl;
        return true;
    }
    
    // 获取可执行文件所在目录
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();
    
    std::cout << "\n开始复制DLL文件到目标目录: " << destDir << std::endl;
    
    int successCount = 0;
    int failCount = 0;
    
    for (const auto& dllName : dllList) {
        std::cout << "正在查找: " << dllName << std::endl;
        
        std::string dllPath = FindDLLFile(dllName, exeDir);
        if (dllPath.empty()) {
            std::cerr << "错误: 无法找到DLL文件: " << dllName << std::endl;
            failCount++;
            continue;
        }
        
        std::cout << "找到DLL: " << dllPath << std::endl;
        
        if (CopyFileToDirectory(dllPath, destDir)) {
            successCount++;
        } else {
            failCount++;
        }
    }
    
    std::cout << "\n复制完成: 成功 " << successCount << " 个，失败 " << failCount << " 个" << std::endl;
    return failCount == 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2 || argc > 4) {
        std::cout << "用法: " << argv[0] << " <可执行文件路径> [选项]" << std::endl;
        std::cout << "选项:" << std::endl;
        std::cout << "  --copy <目标目录>    复制依赖DLL到指定目录" << std::endl;
        std::cout << "  --copy-exe-dir      复制依赖DLL到可执行文件所在目录" << std::endl;
        std::cout << "示例:" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy C:\\DestDir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir" << std::endl;
        return 1;
    }

    auto exe_path = argv[1];
    bool copyMode = false;
    std::string destDir;

    // 解析命令行参数
    if (argc > 2) {
        if (strcmp(argv[2], "--copy") == 0 && argc == 4) {
            copyMode = true;
            destDir = argv[3];
        } else if (strcmp(argv[2], "--copy-exe-dir") == 0) {
            copyMode = true;
            // 获取可执行文件所在目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
        } else {
            std::cerr << "错误: 无效的命令行参数" << std::endl;
            return 1;
        }
    }

    auto dlls = GetDependentDLLs(exe_path);
    
    std::cout << "\n=== 依赖DLL列表 ===" << std::endl;
    for (const auto &dll : dlls)
    {
        std::cout << dll << std::endl;
    }
    std::cout << "总共: " << dlls.size() << " 个DLL" << std::endl;

    // 如果启用了复制模式，则复制DLL文件
    if (copyMode) {
        std::cout << "\n=== 开始复制DLL文件 ===" << std::endl;
        if (CopyDependentDLLs(dlls, exe_path, destDir)) {
            std::cout << "所有DLL文件复制成功!" << std::endl;
        } else {
            std::cout << "部分DLL文件复制失败，请检查错误信息" << std::endl;
            return 1;
        }
    }
    
    return 0;
}