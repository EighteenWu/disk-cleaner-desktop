# DiskClean 自定义规则编写说明

DiskClean 自定义规则使用 YAML。规则通过校验后会在下一次扫描时传给后端，命中的路径会生成清理候选。执行清理时仍会再次应用路径保护、`keep_days`、`exclude` 和强制安全排除项。

规则文件启用了严格字段校验：未定义字段、空必填字段、非法路径或非法枚举值都会导致校验失败。

## 最小示例

```yaml
version: 1
name: Local development cache rules
publisher: local
updated_at: 2026-05-13
rules:
  - id: npm.cache
    name: npm 缓存
    app: npm
    category: 开发工具缓存
    level: 需要确认
    default: false
    paths:
      - "%LOCALAPPDATA%\\npm-cache"
    clean: contents
    keep_days: 14
    close:
      - node.exe
      - npm.exe
    exclude:
      - "**\\_cacache\\tmp\\**"
    note: npm 下载缓存可重新生成，但会影响离线安装和下次安装速度。
```

## 顶层字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `version` | 是 | 当前必须为 `1`。 |
| `name` | 否 | 规则集名称。 |
| `publisher` | 否 | 规则维护者或来源。 |
| `updated_at` | 否 | 更新时间，建议使用 `YYYY-MM-DD`。 |
| `rules` | 是 | 规则列表，至少包含一条规则。 |

`app` 和后端自动识别出的来源只用于展示、筛选和日志归纳，不能覆盖内置保护规则。是否允许清理由风险等级、路径校验、内置保护和最终清理前复检共同决定。

## 规则字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则唯一 ID，只允许字母、数字、`.`、`-`、`_`，且不能在同一文件内重复。 |
| `name` | 是 | 展示名称。 |
| `app` | 是 | 来源应用或工具名。 |
| `category` | 是 | UI 分类，例如 `开发工具缓存`、`应用缓存`、`浏览器缓存`。 |
| `level` | 是 | 风险级别：`推荐清理`、`谨慎清理`、`需要确认`；也支持 `recommended`、`cautious`、`review`、`reviewRequired`。 |
| `default` | 否 | 是否请求默认勾选。只有最终仍是安全推荐项时才可能默认勾选。 |
| `paths` | 是 | 清理目标路径列表，至少一项。 |
| `clean` | 否 | 清理方式：`contents`、`files`、`recycle`、`manual`；默认 `manual`。 |
| `keep_days` | 否 | 保留最近多少天的文件，最大 `365`。未设置时按 `level` 使用默认值。 |
| `close` | 否 | 建议关闭的 Windows 进程名，只允许类似 `chrome.exe` 的进程名。 |
| `exclude` | 否 | 额外排除 glob。 |
| `note` | 是 | 给用户看的清理说明和风险说明。 |

## 风险级别

| `level` | 默认保留天数 | 适用场景 |
| --- | --- | --- |
| `推荐清理` / `recommended` | `3` | 明确可再生的临时文件或缓存，且不包含账号、配置、数据库和用户内容。 |
| `谨慎清理` / `cautious` | `7` | 通常可再生，但可能影响下次启动、索引、下载或构建速度。 |
| `需要确认` / `review` / `reviewRequired` | `7` | 依赖缓存、构建缓存、日志、诊断数据或路径较宽的规则。 |

命中高风险路径特征时，DiskClean 会自动降级风险等级，并取消默认勾选。

## 路径规则

`paths` 必须是 Windows 绝对路径，或以下环境变量开头的路径：

```text
%LOCALAPPDATA%
%LOCALLOWAPPDATA%
%APPDATA%
%USERPROFILE%
%DOCUMENTS%
%TEMP%
%TMP%
%PROGRAMDATA%
%COMMONAPPDATA%
%ALLUSERSPROFILE%
%PUBLIC%
%SYSTEMDRIVE%
%PROGRAMFILES%
%PROGRAMFILES(X86)%
%PROGRAMW6432%
%COMMONPROGRAMFILES%
%COMMONPROGRAMFILES(X86)%
%COMMONPROGRAMW6432%
%WINDIR%
%SYSTEMROOT%
```

推荐写法：

```yaml
paths:
  - "%LOCALAPPDATA%\\Temp\\my-tool"
  - "%APPDATA%\\SomeApp\\Cache"
  - "D:\\scratch\\tool-cache"
```

不要使用：

```yaml
paths:
  - "Cache"
  - "%USERPROFILE%"
  - "C:\\"
  - "%LOCALAPPDATA%\\..\\Roaming"
```

路径不能包含 `..`，也不能把盘符根目录作为清理目标。

## 清理方式

| `clean` | 语义 |
| --- | --- |
| `contents` | 清理目录内容，保留目录本身。 |
| `files` | 清理命中规则的文件。 |
| `recycle` | 通过回收站清理。 |
| `manual` | 只标注，不自动清理。 |

当路径被安全策略判定为危险时，清理方式会被降级或要求用户手动审查。

## 默认勾选规则

`default: true` 只是规则作者的请求，不是最终结果。以下情况不会默认勾选：

- `level` 不是 `推荐清理`。
- 路径命中用户文档、系统目录、程序安装目录、项目目录、依赖安装目录、账号状态、数据库、会话、密钥、钱包等高风险特征。
- 规则来自订阅，且用户还没有确认启用。
- 清理项属于开发依赖缓存、普通应用日志、备份、恢复、自动保存或 Profile 数据。

## 内置保护

以下模式会强制排除：

```text
**\\*token*
**\\*session*
**\\*wallet*
**\\*keychain*
**\\*credential*
**\\*backup*
**\\*recovery*
**\\*autosave*
**\\*profile*
**\\IndexedDB\\**
**\\Local Storage\\**
**\\Session Storage\\**
**\\Sessions\\**
**\\databases\\**
**\\blob_storage\\**
**\\Network\\**
**\\Cookies*
**\\Login Data*
**\\History*
**\\Preferences
**\\Local State
**\\*.db
**\\*.sqlite
**\\*.sqlite3
**\\*.vscdb
```

以下路径或特征会被锁定或降级：

- `%USERPROFILE%`、`%APPDATA%`、`%LOCALAPPDATA%`、`%LOCALLOWAPPDATA%`、`%DOCUMENTS%`、`%PROGRAMDATA%`、`%WINDIR%`、`%SYSTEMROOT%` 根目录。
- 非临时 Windows 系统目录；目前只允许 `%WINDIR%\\Temp`、`%WINDIR%\\SoftwareDistribution\\Download` 和部分诊断、错误报告、崩溃转储路径进入审查。
- `Program Files`、`WindowsApps`、`WpSystem`、`Config.Msi`、用户文档、桌面、图片、视频、音乐、源码、仓库、项目目录。
- Electron / Chromium 应用主体，例如 `resources\\app`、`app.asar`、`app.asar.unpacked`。
- 项目依赖运行目录，例如 `node_modules`、`.venv`、`site-packages`、`vendor`、`.cargo\\registry\\src`。
- 账号、会话、钱包、密钥、凭据、IndexedDB、Local Storage、Session Storage、Cookies、Login Data、History、SQLite、数据库文件。
- 普通应用日志、备份、恢复、自动保存、Profile 数据。
- npm、pnpm、Yarn、pip、uv、Gradle、Pub、NuGet、Composer、Cargo 等开发依赖缓存。

## 订阅规则

订阅链接校验要求：

- 必须使用 `https://`。
- URL 不能包含空白字符。
- host 不能为空，且不能包含 `@`。
- 文件后缀必须是 `.yaml`、`.yml` 或 `.ini`。
- 不支持 `.txt`。
- 内容必须是 UTF-8。
- 文件大小不能超过 `2 MB`。

`.yaml` / `.yml` 会按 DiskClean YAML 规则编译；`.ini` 会按 Winapp2 导入策略转换。订阅规则中的 `default: true` 不会直接生效，必须由用户确认。

## Winapp2 导入

规则面板支持把 Winapp2 `.ini` 内容粘贴到自定义规则文本框，然后点击“导入 Winapp2”。导入器不会直接执行 Winapp2 原始规则，而是把安全子集转换为 DiskClean 规则后再进入扫描流程。

当前导入策略：

- 只导入可以准确映射的 `FileKey=path|fileParameters`。
- `RegKey` 暂不导入。
- 浏览器历史、Cookie、账号会话、`Web Data`、`Local Storage` 等状态数据不导入或降级。
- `%ProgramFiles%`、`%SystemDrive%` 等安装目录或系统根路径会触发审查或跳过。
- 导入规则全部会经过 DiskClean 路径保护、强制排除、`keep_days` 和清理前复检。

## 推荐实践

- 先写 `manual` 或 `需要确认`，确认命中路径准确后再提升为 `谨慎清理` 或 `推荐清理`。
- 优先清理明确可再生的缓存和临时目录。
- 构建产物、依赖缓存、日志和诊断数据默认设为 `需要确认`。
- 不要清理配置、用户数据、状态数据库、项目依赖安装目录和应用运行文件。
- 不要把根目录或过宽路径作为清理目标。
- `note` 要写清楚为什么可清理，以及删除后是否会重新生成。
- 每次新增规则后，在应用的规则面板中先执行校验，再进行扫描和清理验证。
