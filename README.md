# DiskClean

![DiskClean logo](apps/desktop/src/assets/diskclean-logo.png)

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-2563eb)](#系统要求)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24c8db)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://react.dev/)
[![Rust](https://img.shields.io/badge/Rust-stable-f97316)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-16a34a)](LICENSE)

DiskClean 是一个面向 Windows 的桌面磁盘清理工具，基于 Tauri、React 和 Rust 构建。它会按用户选择的磁盘卷扫描缓存、临时文件、构建产物、日志目录和 Windows 清理项，并在清理前展示风险等级、来源、预计释放空间、保留策略和执行计划。对于 NTFS 卷，全盘分析会优先直接解析卷上的 `$MFT`（管理员权限）；失败或非管理员时回退到目录元数据枚举，结果仍可用但更慢。

## 界面预览

<p align="center">
  <img src="docs/design/diskclean-main.png" alt="DiskClean 主界面" width="100%">
</p>

| 规则设置 | 日志中心 |
| --- | --- |
| <img src="docs/design/diskclean-rules.png" alt="DiskClean 规则设置" width="100%"> | <img src="docs/design/diskclean-logs.png" alt="DiskClean 日志中心" width="100%"> |

## 功能亮点

### 扫描与筛选

| 能力 | 说明 |
| --- | --- |
| 多盘符选择 | 自动加载本机卷信息，可按 C/D/E 等盘符选择扫描范围。 |
| 按卷执行扫描 | 扫描请求会把已选盘符传给后端；候选项按所属盘符归档，并可在 UI 中继续按盘符过滤。 |
| 双扫描模式 | 快速扫描用于常见缓存和规则命中，全盘分析会对选中的每个磁盘卷做更完整的候选发现。 |
| 清理档位 | 低/中/高只决定清理范围（简单/中度/深度）。是否遍历整盘由「快速扫描 / 全盘分析」决定。 |
| 管理员加速扫描 | NTFS 全盘分析会优先直接解析 `$MFT` 以获得 logical/allocated 大小；该特性需要管理员权限，非管理员或解析失败时回退为目录枚举，结果仍可用但速度更慢。 |
| 实时扫描状态 | 展示扫描进度、当前后端状态、候选数量、不可清理数量和预计释放空间。 |
| 搜索与过滤 | 支持按路径、分类、规则、风险级别和“仅已选”快速收敛候选项。 |
| 分类视图 | 按临时文件、浏览器缓存、开发依赖缓存、Windows 清理项等分类组织结果。 |

### 候选审查

| 能力 | 说明 |
| --- | --- |
| 风险分级 | 候选项分为推荐、谨慎、危险/需要确认、不可清理等状态。 |
| 来源识别 | 基于 Registry、AppData 路径、Steam 清单、项目目录标记和内置路径规则识别来源应用。 |
| 详情侧栏 | 展示当前候选的来源、路径、风险原因、清理策略、锁定状态和预计释放空间。 |
| 子项预览 | 支持预览目录内容，帮助确认清理范围是否符合预期。 |
| 默认勾选保守 | 只有明确安全、可再生的缓存才可能默认选中，高风险对象默认要求人工确认。 |

### 清理执行

| 能力 | 说明 |
| --- | --- |
| 清理前计划 | 执行前生成清理计划，统计已选项目、预计释放空间、锁定跳过项和删除方式。 |
| 删除方式可控 | 默认移动到 Windows 回收站；永久删除必须由用户显式勾选。 |
| 真实清理进度 | 后端持续上报处理数量、当前路径、百分比和阶段状态。 |
| 可暂停/取消 | 扫描和清理流程提供暂停、继续、取消等控制入口。 |
| 结果汇总 | 清理完成后汇总已清理、跳过、失败原因、释放空间和逐项结果。 |

### 规则系统

| 能力 | 说明 |
| --- | --- |
| 本地规则库 | 只有用户批准的规则才会进入扫描；空库不会回退到打包 YAML。 |
| 推荐规则包 | 一点「使用推荐规则」把打包 YAML 批准进本地库；不会在启动时静默加载。 |
| YAML 自定义规则 | 支持在规则面板直接编写、校验，保存并批准后才会启用。 |
| HTTPS 规则订阅 | 支持加载 `.yaml`、`.yml`、`.ini` 订阅，订阅内容会做大小、编码和 URL 校验。 |
| Winapp2 导入 | 可导入 Winapp2 `.ini` 的安全子集，`RegKey` 和高风险状态数据不会直接执行。 |
| AI 对话生成规则 | 全盘分析后，对话根据占空间目录摘要按大小/路径/说明/影响识别垃圾；点通过才生成并启用规则。Key 只存本机凭据库。 |
| 安全降级 | 规则命中系统目录、用户数据、数据库、会话、密钥、依赖安装目录等路径时会降级或取消默认勾选。 |

### 可观测性与桌面体验

| 能力 | 说明 |
| --- | --- |
| 日志中心 | 按扫描、清理、操作分类记录关键事件、耗时、后端状态和规则加载结果。 |
| 管理员状态 | 明确显示管理员/非管理员状态；非管理员时提示并提供管理员重启入口，以启用 NTFS 直接 `$MFT` 全盘 inventory 能力。 |
| 多语言界面 | 支持中文、英文、日文、法文、德文。 |
| 主题模式 | 支持浅色、深色和跟随系统主题。 |
| 桌面打包 | 基于 Tauri v2，可打包为 Windows 安装包。 |

## 安全设计

DiskClean 默认偏保守，不会把“能删”当成“应该删”：

- 永久删除必须由用户显式启用，默认使用更可恢复的清理路径。
- 回收站清空属于永久删除，内置候选不会默认勾选。
- 盘符根、Windows 系统目录、应用商店安装目录（WindowsApps）不会自动清理。
- Program Files 安装目录、Electron `app.asar`、钱包/令牌/凭据、浏览器 Cookie、历史、IndexedDB、数据库、用户文档和 `node_modules` 会列入结果并默认不勾选，用户确认后可以删除。
- npm、pnpm、Yarn、pip、Gradle、NuGet、Cargo 等开发依赖缓存默认要求用户确认，确认后可删。
- 只有批准进本地规则库的规则才会进入扫描；打包的推荐规则需要一点导入，运行时不会偷偷加载 YAML。再次导入会把未在编辑中的官方包更新到最新版。
- Winapp2 导入会跳过不支持的路径，其余规则仍可保存。
- 清理档位只过滤本次前台清理要用的规则；自动化任务仍使用全部已批准规则。
- AI 对话不会删除文件；发给模型的是目录摘要和候选项聚合，不是全盘每个文件，也不包含 API Key。

日常使用见 [操作手册](docs/user-manual.md)，版本记录见 [CHANGELOG](CHANGELOG.md)。

## 项目结构

```text
apps/desktop/                 Tauri + React 桌面应用
apps/desktop/src/             React UI、状态管理、IPC API 和测试
apps/desktop/src-tauri/       Tauri/Rust 桌面壳、系统命令和本地存储
crates/cleaner-core/          扫描、规则校验、清理计划和执行核心
rules/default-rules.yaml      推荐规则包文档（需一点导入，运行时不自动加载）
CHANGELOG.md                  版本更新日志
docs/user-manual.md           使用操作手册
docs/custom-rules.md          自定义规则编写说明
docs/design/                  设计说明和界面预览
```

## 系统要求

- Windows 10/11
- Node.js 18+ 和 pnpm
- Rust stable
- Tauri v2 所需的 Windows 构建工具

## 本地开发

```powershell
pnpm install
pnpm dev
```

常用命令：

| 命令 | 用途 |
| --- | --- |
| `pnpm dev` | 启动桌面应用开发环境。 |
| `pnpm lint` | 运行 TypeScript 类型检查。 |
| `pnpm test` | 运行前端单元测试。 |
| `pnpm build` | 构建前端产物。 |
| `pnpm tauri build` | 打包 Tauri 桌面安装包。 |
| `cargo test` | 运行 Rust 工作区测试。 |

## 打包产物

Tauri 打包成功后，安装包默认输出到：

```text
target/release/bundle/msi/
target/release/bundle/nsis/
```

## 自定义规则

DiskClean 支持在规则面板中编写 YAML 规则，也支持加载 HTTPS 订阅：

```yaml
version: 1
name: Local cache rules
publisher: local
rules:
  - id: example.tool.cache
    name: 示例工具缓存
    app: ExampleTool
    category: 开发工具缓存
    level: 需要确认
    default: false
    paths:
      - "%LOCALAPPDATA%\\ExampleTool\\Cache"
    clean: contents
    keep_days: 7
    close:
      - example.exe
    note: 删除后可重新生成，但会影响下次启动或下载速度。
```

完整字段、路径约束、安全降级和 Winapp2 导入策略见 [docs/custom-rules.md](docs/custom-rules.md)。

## 贡献

欢迎提交问题、规则补充和改进建议。涉及清理行为的改动请优先说明：

- 目标路径为什么可以清理。
- 删除后是否可重新生成。
- 是否可能影响账号、会话、配置、数据库或用户文件。
- 默认勾选是否足够保守。

## 许可证

本项目基于 [MIT License](LICENSE) 开源。
