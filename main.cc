#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#pragma comment(lib, "dbghelp.lib")

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

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "用法: " << argv[0] << " <可执行文件路径>" << std::endl;
        std::cout << "示例: " << argv[0] << " C:\\Path\\To\\YourApp.exe" << std::endl;
        return 1;
    }

    auto exe_path = argv[1];
    auto dlls = GetDependentDLLs(exe_path);
    
    std::cout << "\n=== 依赖DLL列表 ===" << std::endl;
    for (const auto &dll : dlls)
    {
        std::cout << dll << std::endl;
    }
    std::cout << "总共: " << dlls.size() << " 个DLL" << std::endl;
    
    return 0;
}