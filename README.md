# 配置漏检工具箱（Config Leak Checker）

**合规声明（请务必阅读）：本工具仅可用于检测你本人所有、或已获得明确书面授权的本地文件、目录与备份归档。严禁使用本工具检测未授权第三方数据，严禁将其用于非法窃取凭据、入侵准备、违规审计或其他违法活动。工具只做静态特征匹配，不提供密码爆破、凭据解密、漏洞利用或远程访问能力；检测结果可能包含误报。使用者应自行承担因违规使用产生的一切责任。**

本工具完全离线运行，只监听 `127.0.0.1` 回环地址，不会向任何服务器发送文件、路径、检测结果或使用统计。所有测试样本均为伪造模拟数据，不包含真实密钥、真实企业信息或真实公民信息。

## 1. 项目定位与能力边界

### 1.1 项目是什么

- 本地静态配置安全检测工具，核心场景是发现明文凭据、弱安全配置和敏感信息暴露。
- 带轻量本地 Web 界面，服务启动后可完成路径选择、检测、筛选、详情查看与报告下载。
- 规则采用 YAML 声明式定义，放在 `rules/` 即可被下一次检测自动加载。
- 支持普通配置文件、压缩归档和模拟固件中的明文配置片段。
- 所有识别结果可溯源到文件相对路径、行号和规则 ID，敏感匹配内容自动掩码。
- 自带可离线运行的全量测试样本与测试用例。

### 1.2 项目不是什么

- 不是动态网络扫描器，不进行端口探测、服务识别或远程漏洞验证。
- 不是 Web 漏洞利用工具，不发送任何攻击载荷。
- 不是密码管理器，不保存、托管或恢复用户凭据。
- 不是在线合规审计平台，不上传数据，不生成云端工单。
- 不是分布式扫描系统，只支持单机、单用户、本地内存任务。
- 不是通用 CLI 扫描器，核心操作入口是本地 Web 页面；`run_web.py` 和 `run_tests.py` 仅作为启动入口。

### 1.3 与动态扫描类项目的差异

本工具与 scan-lab 一类动态 Web 扫描项目没有业务重叠：本工具只读取用户显式指定的本地静态文件，不启动靶场、不发起网络探测、不依赖运行态服务。它不解析加密文件，不逆向固件文件系统，只匹配模拟固件镜像中带特征头的明文配置片段。

### 1.4 明确不支持的能力

1. 动态网络扫描、端口探测、服务指纹识别、漏洞利用。
2. 密码爆破、凭据解密、加密文件内容解析、完整密钥恢复。
3. 完整固件逆向、固件文件系统解析、二进制反编译。
4. 多用户权限、多人协作、分布式调度、多节点检测。
5. 自定义报告模板、第三方平台对接、消息推送、云端同步。
6. 远程文件拉取、云存储配置读取、在线凭据获取。
7. 以纯 CLI 批量检测作为核心使用方式。
8. 集成第三方在线规则库或在线特征库；所有规则本地内置、离线可改。

## 2. 功能概览

| 编号 | 能力 | 当前实现 |
| --- | --- | --- |
| F1 | 多源静态文件解析 | YAML/YML、TOML、INI、CONF、ENV、JSON、XML；zip、tar、tar.gz、tar.bz2；模拟固件特征头片段 |
| F2 | 声明式规则引擎 | 内置 43 条规则，支持正则、键名精确、数值范围、弱口令字典；YAML 规则热加载 |
| F3 | 硬编码凭据检测 | 密码、API Key、令牌、数据库 URL、云 AK/SK、私钥头等；自动排除环境变量/模板占位符/空值；结果掩码 |
| F4 | 弱安全配置检测 | 109 项弱口令字典、777 权限、数据库 `%` 远程访问、调试模式、SSLv3/TLS1.0、匿名访问、认证关闭等 |
| F5 | 敏感信息检测 | 保留测试号段手机号、虚构身份证格式、内网 IP、内部域名、测试账号、内部日志路径、模拟员工编号 |
| F6 | 风险聚合溯源 | 同文件、同规则、同匹配值聚合去重；不同文件独立记录；路径/等级/规则/类别筛选 |
| F7 | 本地报告导出 | 自动生成 JSON/CSV 全量报告；支持按筛选条件导出；报告只写入本地 `output/` |
| F8 | 本地 Web 操作 | 标准库 HTTP 服务，`127.0.0.1:8765`，异步进度轮询、筛选、详情、下载，全部静态资源内置 |

### 2.1 支持的文件格式

- 配置：`.yaml`、`.yml`、`.toml`、`.ini`、`.conf`、`.env`、`.json`、`.xml`
- 归档：`.zip`、`.tar`、`.tar.gz`、`.tgz`、`.tar.bz2`、`.tbz2`，自动读取内部配置文件
- 模拟固件：`.bin`、`.img`、`.fw`，只提取下列标记之间的 UTF-8 明文片段：

```text
# FW-CONFIG-BEGIN
password: example
# FW-CONFIG-END
```

无特征头、无法解码、损坏、加密或非文本的目标会被标记为“跳过”，不会中断整体检测。归档内容只在内存中读取，不落盘解压，因此不会写出归档中的路径。

## 3. 目录结构

```text
config-leak-checker/
├── README.md
├── requirements.txt
├── run_web.py
├── run_tests.py
├── core/
│   ├── file_loader.py
│   ├── rule_engine.py
│   ├── result_manager.py
│   ├── report_exporter.py
│   └── web_handler.py
├── rules/
│   ├── hardcoded_credential.yaml
│   ├── weak_security.yaml
│   └── sensitive_info.yaml
├── web/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── fixtures/
│   ├── normal_samples/
│   ├── risky_samples/
│   ├── archive_samples/
│   └── firmware_samples/
├── tests/
├── output/
└── .gitignore
```

## 4. 离线安装指南

### 4.1 环境要求

- Python 3.10 或更高版本（已在 Python 3.13 环境验证）
- 支持 Windows、Linux、macOS 的本地文件系统
- 不需要数据库、浏览器内核、Node.js 或任何前端构建工具
- 运行期依赖仅为纯 Python 包及 PyYAML 的小型 wheel

### 4.2 在线准备依赖（有网络时）

```bash
python -m pip install -r requirements.txt
```

依赖精确版本见 `requirements.txt`：

```text
PyYAML==6.0.2
tomli==2.5.0
pytest==8.4.2
```

### 4.3 下载 wheel 并断网安装（目标机无网络）

在一台与目标机 **Python 版本、操作系统、CPU 架构一致**的联网机器上执行：

```bash
python -m pip download -r requirements.txt -d wheelhouse
```

将整个项目目录与 `wheelhouse/` 一起复制到断网机器，然后执行：

```bash
python -m pip install --no-index --find-links=wheelhouse -r requirements.txt
```

如果使用虚拟环境，先在目标机创建并激活虚拟环境：

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install --no-index --find-links=wheelhouse -r requirements.txt
```

安装完成后可断网执行 `python run_tests.py` 验证。项目没有私有源、CDN、在线字体、在线脚本或遥测依赖。

### 4.4 离线自检

```bash
python run_tests.py
python run_web.py
```

浏览器访问 `http://127.0.0.1:8765/`。服务只接受回环地址，不能通过绑定 `0.0.0.0` 对外暴露。

## 5. 快速上手

### 5.1 单命令启动

```bash
python run_web.py
```

默认监听 `http://127.0.0.1:8765/`。如默认端口被占用：

```bash
python run_web.py --port 8766
```

端口变化不影响“仅监听 127.0.0.1”的约束。

### 5.2 Web 界面检测流程

1. 在输入框中填写本机文件或目录的绝对路径、相对路径，例如 `fixtures/risky_samples`。
2. 点击“开始检测”。页面会显示文件加载、规则匹配的实时进度。
3. 检测完成后查看高/中/低风险统计、跳过文件与风险表格。
4. 使用风险等级、风险类别、规则 ID、文件路径筛选。
5. 点击任意结果行查看完整描述、掩码片段、行号和修复建议。
6. 点击“完整报告 JSON/CSV”下载全量报告；筛选后点击“筛选报告 JSON/CSV”导出当前视图。

服务启动后，点击页面中的“含风险样本”“正常配置样本”“归档样本”可快速填入仓库内示例路径。

### 5.3 报告位置与内容

- 每次检测完成，自动在 `output/` 写入 `config_leak_report_*.json` 和 `config_leak_report_*.csv`。
- 筛选导出会额外写入 `config_leak_filtered_*.json/.csv`。
- JSON 顶层包含 `scan_time`、`finished_at`、`statistics`、`filters`、`skipped`、`findings`。
- `statistics` 包含 `total_files`、`scanned_files`、`skipped_files`、`high`、`medium`、`low`、`total_findings` 等统计。
- CSV 使用标准表头，统计字段位于每行的前置列；无风险时写入一行 `record_type=summary` 的记录。
- 匹配片段字段为 `matched_masked`，只保留前 2 位与末 1 位，短值全部替换为 `*`。
- 所有报告只写入本地 `output/`，没有任何上传或同步逻辑；`output/` 已在 `.gitignore` 中忽略。

### 5.4 添加自定义规则

1. 在 `rules/` 下新建任意 `.yaml` 或 `.yml` 文件。
2. 按第 6 节格式编写一条或多条规则。
3. 不需要修改 Python 代码，也不需要重启服务；下一次检测或下次打开规则概览时会自动加载。
4. 规则 ID 重复、字段缺失、类型错误的规则会被拒绝加载，其他有效规则继续工作。通过 `/api/rules` 或页面“已加载规则概览”查看数量；界面会提示未成功加载的规则数。

## 6. 规则编写规范

### 6.1 文件结构

```yaml
category: hardcoded_credential   # 文件默认类别，可被单条规则覆盖
version: 1
rules:
  - id: HC-900
    name: 自定义密码规则
    severity: high
    description: 发现硬编码密码，读取配置者可直接获得凭据。
    remediation: 移除密码并改为环境变量注入。
    match:
      type: regex
      pattern: >-
        (?i)\bpassword\s*[:=]\s*["']?([^"'\s#]{4,})
      capture_group: 1
      ignore_placeholder: true
```

必填字段：`id`、`severity`、`description`、`remediation`、`match`。推荐填写 `name`。类别必须是 `hardcoded_credential`、`weak_security`、`sensitive_info` 之一；等级必须是 `high`、`medium`、`low`。

### 6.2 匹配类型一：正则匹配（regex）

```yaml
match:
  type: regex
  pattern: >-
    \bAKIA[A-Z0-9]{16}\b
  capture_group: 0
  value_pattern: ''       # 可选：对捕获值再做一次正则过滤
  ignore_placeholder: true
```

- `pattern` 使用 Python `re` 语法，按行匹配。
- `capture_group` 指定要展示和掩码的分组；分组不存在时回退到整个匹配。
- 规则默认自动排除 `${ENV}`、`$ENV`、`{{TEMPLATE}}`、`<PLACEHOLDER>`、`%ENV%`、空值和常见占位词。
- 建议凭据规则使用捕获组，只捕获敏感值，避免把键名或注释一起掩码。

### 6.3 匹配类型二：键名精确匹配（key）

```yaml
match:
  type: key
  keys: [debug, debug_mode]
  value_pattern: >-
    (?i)^(?:true|1|on|yes)$
```

- 从 YAML、JSON、TOML、INI、ENV、CONF、简单 XML 行中提取键值对。
- `keys` 大小写不敏感，必须与解析出的键名相等。
- `value_pattern` 可选，用于限定时值内容。

### 6.4 匹配类型三：值范围判定（range）

```yaml
match:
  type: range
  keys: [password_min_length]
  min_value: 0
  max_value: 7
```

- 对键值中的数值执行闭区间判断。
- `min_value` 与 `max_value` 至少提供一个；边界必须可转换为整数。
- 适用于密码长度、超时时间、权限数字等可量化配置。

### 6.5 弱口令字典（weak_password）

```yaml
match:
  type: weak_password
  keys: [password, passwd, pwd]
  values:
    - 'admin123'
    - 'welcome1'
```

弱口令字典值是规则的一部分；内置规则 WS-014 提供 109 项模拟弱口令值。比较时忽略大小写，仍会自动过滤占位符。

### 6.6 规则 ID 与等级

- 内置前缀：`HC-` 硬编码凭据、`WS-` 弱安全配置、`SI-` 敏感信息。自定义规则建议使用组织前缀，如 `ORG-001`。
- ID 必须全局唯一；重复 ID 会被拒绝，避免覆盖内置规则造成不可预期结果。
- `high`：直接凭据泄露、认证绕过、严重弱配置。
- `medium`：敏感信息暴露、会话/CORS/Cookie 等需尽快修复的问题。
- `low`：内部域名、测试账号、日志路径等辅助信息暴露。
- 修改内置规则后需重新检测；项目不提供在线规则更新，避免引入不可控外部内容。

## 7. 测试执行指南

### 7.1 单命令全量测试

```bash
python run_tests.py
```

等价于在项目根目录执行：

```bash
python -m pytest tests -q
```

### 7.2 覆盖范围

- `test_file_loader.py`：格式识别、8 类配置解析、归档读取、加密/损坏/超大/空文件跳过、固件特征头。
- `test_rule_engine.py`：内置规则完整性、自定义规则、三类主要匹配逻辑、弱口令、占位符、错误规则。
- `test_result_manager.py`：掩码、聚合去重、跨文件独立记录、筛选、统计。
- `test_report_exporter.py`：JSON/CSV 字段、头部统计、空报告、路径穿越防护、掩码。
- `test_web_handler.py`：静态资源、异步任务、进度、结果筛选、筛选导出、下载、参数错误、任务失败。
- `test_integration_flow.py`：四类 fixture、正常配置零误报、风险样本规则全覆盖、归档/固件、离线资源合规、行数与编码。
- 所有测试仅使用本地临时目录和 `fixtures/`，不访问外部资源。

### 7.3 断网专项验证步骤

1. 在有网络环境按 4.3 下载 wheel 并安装依赖。
2. 断开网络（或关闭网卡/使用网络隔离环境）。
3. 执行 `python run_tests.py`，确认全部通过。
4. 执行 `python run_web.py`，浏览器打开 `http://127.0.0.1:8765/`。
5. 检测 `fixtures/risky_samples`，确认进度、筛选、详情、JSON/CSV 下载正常。
6. 检查 `output/` 下生成报告，页面无 CDN、字体或脚本加载失败提示。

如需单独统计覆盖率（非运行必需，可使用额外的 coverage 工具）：

```bash
python -m pytest tests --cov=core --cov-branch --cov-report=term-missing
```

## 8. 常见问题（FAQ）

### 8.1 加密文件或损坏压缩包会怎么处理？

工具不会解密、爆破或修复。加密归档条目、损坏归档、无法按 UTF-8 解码的文件、空文件、缺少固件特征头的镜像会被标记为“跳过文件”，记录原因，并继续检测其他文件。

### 8.2 发现误报怎么办？

先记录规则 ID、文件路径、行号和匹配片段，确认目标值是否为占位符或测试数据。当前版本没有在线误报申诉通道。对确认的误报，可在本地对应规则中设置 `enabled: false` 临时禁用，或将规则复制为自定义规则后调整正则；不建议在生产环境盲目关闭整类规则。修复规则后重新执行 `python run_tests.py`，确保没有影响其他样本。

### 8.3 规则如何更新？

把新的 YAML 文件放入 `rules/`，下一次检测自动加载。更新后建议：

1. 在 Web 页面展开“已加载规则概览”查看数量和错误提示。
2. 运行 `python run_tests.py`，确认无重复 ID、正则错误和回归。
3. 用 `fixtures/normal_samples` 复核误报，用 `fixtures/risky_samples` 复核检出。

项目不连接任何在线规则库，也不会自动下载规则。

### 8.4 端口 8765 被占用怎么办？

使用 `python run_web.py --port 8766`，或结束占用端口的本地进程。服务始终只监听 `127.0.0.1`，不会因为换端口而暴露到局域网。

### 8.5 归档中的文件为什么没有全部被扫描？

只扫描归档内的受支持配置文件；非配置条目会显示为跳过。嵌套归档不递归处理，单个文件、归档条目数和归档展开大小都有限制，以防止本地资源耗尽。

### 8.6 为什么检测不到固件里的配置？

当前版本只识别 `# FW-CONFIG-BEGIN` 与 `# FW-CONFIG-END` 之间的 UTF-8 明文片段，不做完整固件逆向或文件系统解析。没有特征头的二进制镜像会被跳过，这是设计边界而非故障。

### 8.7 检测结果会上传吗？

不会。服务只监听回环地址，代码中没有外部网络请求；报告只写入本地 `output/`。工具也不会读取用户未显式输入的文件路径。

## 9. 安全与数据声明

- 所有 fixture 中的人名、手机号、证件号、域名、IP、密钥均为虚构模拟值。
- 手机号仅使用保留测试格式 `1990000xxxx`；证件号使用无效前缀 `999999`；云访问密钥是明显的假值。
- 匹配到的敏感值仅以掩码形式进入内存结果与本地报告。
- `output/`、Python 缓存、IDE 配置和虚拟环境已加入 `.gitignore`。
- 本项目不提供任何对外网络接口、用户认证、多租户隔离或公网部署能力，请勿将服务反向代理到公网。

---

配置漏检工具箱 v1.0 · 仅用于授权的本地静态配置检测。
