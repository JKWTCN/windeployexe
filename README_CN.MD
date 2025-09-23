# WinDeploy - Windows 依赖 DLL 分析与部署工具

## 项目简介

WinDeploy 是一个命令行工具，用于分析 Windows 可执行文件（.exe）的依赖 DLL，并可以选择性地将这些 DLL 文件复制到指定目录。该工具特别适用于 Windows 应用程序的部署和分发，帮助开发者收集所有必要的依赖库。

## 功能特点

- 分析 Windows 可执行文件的 PE 头，提取依赖的 DLL 列表
- 支持在多个位置搜索 DLL 文件（可执行文件目录、系统目录、PATH 环境变量等）
- 可选择将依赖的 DLL 复制到指定目录
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
# 分析可执行文件的依赖 DLL
win_deploy.exe C:\Path\To\YourApp.exe
```

### 复制依赖 DLL 到指定目录

```bash
# 复制依赖 DLL 到指定目录
win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir
```

### 复制依赖 DLL 到可执行文件所在目录

```bash
# 复制依赖 DLL 到可执行文件所在目录
win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir
```

### 命令行参数

```
用法: win_deploy.exe <可执行文件路径> [选项]
选项:
  --copy <目标目录>    复制依赖DLL到指定目录
  --copy-exe-dir      复制依赖DLL到可执行文件所在目录
示例:
  win_deploy.exe C:\Path\To\YourApp.exe
  win_deploy.exe C:\Path\To\YourApp.exe --copy C:\DestDir
  win_deploy.exe C:\Path\To\YourApp.exe --copy-exe-dir
```

## 工作原理

1. **PE 文件分析**：工具读取可执行文件的 PE 头，解析导入表（Import Directory），获取所有依赖的 DLL 名称。
2. **DLL 搜索**：按照以下顺序搜索 DLL 文件：

   - 可执行文件所在目录
   - 当前工作目录
   - 系统目录（System32）
   - Windows 目录
   - PATH 环境变量中的所有目录
3. **文件复制**：如果指定了复制选项，工具会将找到的 DLL 文件复制到目标目录，自动创建目录结构并跳过已存在的文件。

## 技术细节

- 使用 Windows API 进行文件操作和 PE 文件解析
- 实现了 RVA（相对虚拟地址）到文件偏移量的转换
- 使用 RAII 模式管理 Windows 句柄和内存映射视图
- 支持多种 PE 文件架构的检测
- 包含完整的错误处理和边界检查

## 项目结构

```
windeployexe/
├── main.cc              # 主程序源代码
├── CMakeLists.txt       # CMake 构建配置
├── CMakeSettings.json   # Visual Studio CMake 设置
├── .gitignore           # Git 忽略文件
└── README.MD           # 项目说明文档
```

## 许可证

MIT

## 贡献

欢迎提交问题报告和功能请求。如果您想贡献代码，请确保：

1. 代码符合项目的编码风格
2. 添加适当的注释和文档
3. 确保代码在目标平台上正确编译和运行

## 联系方式

如有问题或建议，请通过以下方式联系：

- 创建 GitHub Issue
- 发送邮件至项目维护者
