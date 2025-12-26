# WinDeploy - Windows 依赖 DLL 分析与部署工具

**中文** | [**English**](README.md)

## 项目简介

WinDeploy 是一个命令行工具，用于分析 Windows 可执行文件（.exe）和动态链接库（.dll）的依赖关系，并可以选择性地将这些依赖的 DLL 文件复制到指定目录。该工具特别适用于 Windows 应用程序的部署和分发，帮助开发者收集所有必要的依赖库。

## 功能特点

- 分析 Windows 可执行文件的 PE 头，提取依赖的 DLL 列表
- 支持递归分析所有层级的 DLL 依赖关系
- 支持在多个位置搜索 DLL 文件（可执行文件目录、系统目录、PATH 环境变量等）
- 支持从文件加载额外的搜索目录和忽略列表
- 可选择将依赖的 DLL 复制到指定目录
- 自动识别并跳过 Windows 系统核心 DLL（如 KERNEL32.dll、USER32.dll 等）
- 支持 x64 和 x86 架构的 PE 文件
- 使用 RAII 模式管理 Windows 资源，确保资源正确释放
- 详细的错误处理和日志输出

## 构建要求

- Windows 操作系统
- CMake 3.10 或更高版本
- 支持 C++17 的编译器（推荐使用 Visual Studio 2017 或更高版本）
- Ninja 构建系统（可选）

## 构建方法

### 使用 Visual Studio

1. 打开 Visual Studio
2. 选择"打开本地文件夹"，选择项目根目录
3. Visual Studio 会自动检测 CMakeLists.txt 并配置项目
4. 选择构建配置（Debug 或 Release）
5. 点击"生成"->"生成解决方案"

### 使用命令行

```bash
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release

# 构建项目
cmake --build .
```

构建完成后，可执行文件将位于 `build/bin` 目录下。

## 使用方法

### 基本用法

```bash
# 分析可执行文件的依赖 DLL（仅第一层）
win_deploy.exe C:\Path\To\YourApp.exe

# 分析 DLL 文件的依赖
win_deploy.exe C:\Path\To\YourLibrary.dll

# 递归分析所有层级的依赖 DLL
win_deploy.exe C:\Path\To\YourApp.exe --recursive

# 递归分析并指定最大深度（默认 20）
win_deploy.exe C:\Path\To\YourApp.exe --recursive 10
```

### 发布模式

```bash
# 发布模式：递归分析依赖（深度为2）并复制到可执行文件所在目录
win_deploy.exe C:\Path\To\YourApp.exe --release

# 发布模式并指定递归深度
win_deploy.exe C:\Path\To\YourApp.exe --release 3
```

### 复制依赖 DLL

```bash
# 复制依赖 DLL 到指定目录
win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir

# 复制依赖 DLL 到可执行文件所在目录
win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir

# 复制所有 DLL（包括系统核心 DLL）
win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir --copy-all
```

### 使用额外的搜索目录

```bash
# 从文件加载额外的搜索目录
win_deploy.exe C:\Path\To\YourApp.exe --search-dirs search_paths.txt

# search_paths.txt 文件格式（每行一个目录路径）：
# C:\MyLibs\bin
# D:\ThirdParty\libs
# # 以 # 或 ; 开头的行会被视为注释
```

### 使用忽略列表

```bash
# 从文件加载忽略列表
win_deploy.exe C:\Path\To\YourApp.exe --ignore-dll ignore.txt

# ignore.txt 文件格式：
# # 可以包含 DLL 名称
# unwanted.dll
# # 可以包含完整路径
# C:\Windows\System32\skip_this.dll
# # 可以包含目录路径（该目录下的所有 DLL 会被忽略）
# C:\TemporaryLibs
```

### 组合使用

```bash
# 发布模式 + 额外搜索目录 + 忽略列表
win_deploy.exe C:\Path\To\YourApp.exe --release --search-dirs search_paths.txt --ignore-dll ignore.txt
```

### 命令行参数

```
用法: win_deploy.exe <可执行文件路径|DLL文件路径> [选项]

选项:
  --release [depth]     发布模式：递归分析依赖（默认深度：2）并复制到文件所在目录
  --recursive [depth]   递归分析所有 DLL 依赖（默认深度：20）
  --copy <目标目录>     复制依赖 DLL 到指定目录
  --copy-exe-dir        复制依赖 DLL 到文件所在目录
  --copy-all            复制所有 DLL（包括系统核心 DLL）
  --search-dirs <文件>  从文件加载额外的搜索目录（每行一个路径）
  --ignore-dll <文件>   从文件加载忽略列表（DLL 名称、路径或目录）

示例:
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

**注意**：

- 默认情况下，系统核心 DLL（如 KERNEL32.dll、USER32.dll 等）会在复制时被自动跳过
- 使用 `--copy-all` 参数可以复制所有 DLL，包括系统核心 DLL
- `--release` 模式等同于 `--recursive 2 --copy-exe-dir`

## 工作原理

1. **PE 文件分析**：工具读取可执行文件或 DLL 的 PE 头，解析导入表（Import Directory）和延迟加载导入表，获取所有依赖的 DLL 名称。
2. **递归分析**：如果启用递归模式，工具会逐层分析每个依赖 DLL 的依赖关系，直到达到最大递归深度或所有依赖都被分析完毕。
3. **DLL 搜索**：按照以下优先级顺序搜索 DLL 文件：

   - **额外指定的搜索目录**（通过 `--search-dirs` 参数指定，优先级最高）
   - 被分析文件所在目录
   - 当前工作目录
   - 系统目录（System32）
   - Windows 目录
   - PATH 环境变量中的所有目录
4. **文件复制**：如果指定了复制选项，工具会将找到的 DLL 文件复制到目标目录：

   - 自动识别并跳过 Windows 系统核心 DLL（除非使用 `--copy-all`）
   - 跳过在忽略列表中的 DLL
   - 自动创建目标目录
   - 跳过已存在的文件

## 技术细节

- 使用 Windows API 进行文件操作和 PE 文件解析
- 实现了 RVA（相对虚拟地址）到文件偏移量的转换
- 支持解析常规导入表和延迟加载导入表
- 使用 RAII 模式管理 Windows 句柄和内存映射视图
- 支持多种 PE 文件架构的检测（x64、x86）
- 包含完整的错误处理和边界检查
- 自动检测系统核心 DLL 列表，包括 KERNEL32、USER32、GDI32、ADVAPI32 等

## 项目结构

```
windeployexe/
├── main.cc              # 主程序源代码
├── CMakeLists.txt       # CMake 构建配置
├── CMakeSettings.json   # Visual Studio CMake 设置
├── .gitignore           # Git 忽略文件
├── README.MD            # 项目说明文档（英文）
└── README_CN.md         # 项目说明文档（中文）
```

## 许可证

MIT
