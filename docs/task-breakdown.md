# AgentGuard 任务清单拆解

## 读者与用途

本文面向后续继续实现 AgentGuard 的开发者。读完后应该能够按阶段领取任务、理解依赖关系、明确每个任务的验收方式, 并把当前可运行骨架逐步推进到可展示的 MCP 工具安全与 Agent 轨迹评测网关。

拆解原则:

- 每个阶段都交付一个可运行、可测试、可演示的闭环。
- 优先完成能降低最大不确定性的任务: 真实 MCP 配置扫描、运行时策略拦截、trace 可追踪、eval 可量化。
- 每个任务都要有验收标准, 不接受“代码写完但无法证明”的完成状态。
- 第一版不做大平台, 不做复杂 UI, 不做完整沙箱, 先把 CLI + Gateway + Eval + Report 闭环做扎实。

## 当前基线

M0 骨架已完成:

- Python 包、CLI、FastAPI gateway、Pydantic 模型、YAML policy、SQLite trace、JSONL evaluator 和报告模块已存在。
- 示例 MCP 配置、策略文件和 5 条安全 case 已存在。
- 本地验证已通过: pytest、ruff、scan smoke、eval smoke。

接下来任务从 M1 开始。

## 执行进度

- 2026-07-08: 在 `codex/m1-config-scanner` 分支开始顺序执行任务清单。
- 2026-07-08: M1.1 已完成。新增 6 个 MCP config fixture, 覆盖 `mcpServers`、`servers` 字典、`servers` 数组、YAML、缺失 `command`、非法 `args`、非法 `env`; scanner 现在会对非法 server 字段输出清晰错误; CLI 非法配置路径返回非 0 且不暴露 traceback。
- 2026-07-08: M1.2 已完成。新增 server 级风险 fixture, 覆盖敏感 env、危险启动命令、未固定 `npx/uvx` 包来源、高权限目录参数; 每类风险至少 2 条测试 case; Markdown scan 报告可按 server 展示风险 evidence。
- 2026-07-08: M1.3 已完成。scan Markdown 报告新增 Risk Distribution; JSON 报告保留结构化 risks; SARIF 报告测试覆盖 rules/results; CLI `scan --output` 写文件路径已验证。
- 2026-07-08: M2.1 已完成。`infer_capabilities` 现在覆盖 filesystem read/write、shell execution、network egress、database access、browser automation、credential/env access; 每类至少 2 条测试, 并验证一个工具可同时拥有多个 capability。
- 2026-07-08: M2.2 已完成。新增 20 条 tool poisoning 描述注入回归样例, 覆盖忽略/覆盖指令、读取凭据、外发敏感内容、隐藏/系统/developer prompt、绕过策略; `tool_description_injection` 命中项保留匹配片段 evidence 和 recommendation, 并验证安全描述不误报。
- 2026-07-08: M2.3 已完成。新增 16 条 schema 风险回归 case 和分数/负例测试, 覆盖 `command/cmd`、`path/file/filename`、`url/endpoint/webhook`、无类型 object、宽 `additionalProperties`、缺失 `required`; schema ambiguity 风险输出中高等级、结构化 evidence 和可解释分数。
- 2026-07-08: M3.1 已完成。文件系统策略新增规范化路径测试和 20 个 deny case, 覆盖 `.env`、SSH key、pem、cookies、`../`、Windows/POSIX 绝对路径、反斜杠逃逸、嵌套 path 参数; policy evidence/recommendation 明确 parent traversal 与 symlink-resolved escape 风险。
- 2026-07-08: M3.2 已完成。Shell 策略新增 13 条危险命令回归 case, 覆盖删除、格式化、权限破坏、`curl/wget | sh/bash`、PowerShell `iwr/Invoke-WebRequest | iex/Invoke-Expression` 和 encoded command; `shell/run_command/exec/execute/bash/powershell/pwsh` 默认 deny, 显式 allow 下 `pwd/ls/Get-Location` 可通过。
- 2026-07-08: M3.3 已完成。网络外发策略新增 allowlist、内网/localhost/metadata deny 和跨工具外发标记测试; 外部 URL 默认 confirm, `network.allowed_domains` 命中时 allow, private/loopback/link-local/metadata host 输出 `internal_network_egress` 并 deny。
- 2026-07-08: M3.4 已完成。脱敏策略新增递归参数脱敏、tool result 摘要脱敏、authorize trace 不落原始 secret、evaluator redaction coverage 测试; `PolicyDecision` 现在输出 `redactionCount`, 嵌套 token/secret/password/api_key 均会计数并替换为 `***REDACTED***`。
- 2026-07-08: M4.1 已完成。FastAPI TestClient 契约测试覆盖 `/healthz`、`/v1/tool-calls:authorize`、`/v1/tool-calls`、`/v1/traces`、`/v1/runs/{run_id}/trace`; deny 返回 403, confirm 返回 409, authorize 只写 policy_decision 不写 tool_result。
- 2026-07-08: M4.2 已完成。新增 `ToolAdapter` 协议、`MockToolAdapter` 和 `ToolAdapterError`; gateway 支持 adapter 注入, deny/confirm 不执行 adapter, allow 返回结构化 mock result, adapter 错误返回 502 并记录 `tool_error` trace event。
- 2026-07-08: M4.3 已完成。完整 tool call trace 现在按顺序记录 `policy_decision`、`tool_call`、`tool_result`; 阻断请求只记录 policy decision; adapter 错误记录 `tool_error`; call 链路中的参数摘要和结果摘要均验证不落原始 secret。
- 2026-07-08: M5.1 已完成。`security_cases.jsonl` 扩展到 85 条, 覆盖 20 normal、20 tool poisoning、10 path escape、10 sensitive file、10 dangerous shell、10 network egress、5 cross-tool exfiltration; evaluator 支持可选 `tool` 元数据 case, poisoning case 会通过 metadata analyzer 纳入 `tool_description_injection` 风险召回。
- 2026-07-08: M5.2 已完成。`EvaluationResult` 新增 `categoryMetrics`, JSON/Markdown eval report 输出分类通过率; 指标单测覆盖空数据、全安全、全风险、混合失败, 失败 case 保留 expected/actual decision 和 pass 状态。
- 2026-07-08: M5.3 已完成。新增 failure demo eval case 和 `docs/report-samples/` 下 Markdown/JSON/SARIF 三份评测报告样例; Markdown eval report 增加风险分布和失败样例区块, README 已引用样例报告。
- 2026-07-08: M6.1 已完成。README 明确项目定位为工具安全闸门、轨迹黑盒和回放评测器; quick start、scan 输出样例、eval 指标样例、报告样例链接和安全边界已补齐。
- 2026-07-08: M6.2 已完成。新增面试讲解文档, 覆盖一句话定位、30 秒版本、2 分钟版本、5 分钟架构展开和常见追问; README 文档索引已链接该材料。
- 2026-07-08: M6.3 已完成。新增简历 bullet 文档, 提供稳健版 4 条和 Agent 工程基础设施版 4 条, 并列出当前证据边界与不得夸大的未实现能力。
- 2026-07-08: M6.4 已完成。新增项目复盘与面试问答文档, 串联里程碑回顾、工程取舍、证据索引、演示命令和高频追问; README 文档索引已链接该材料。
- 2026-07-08: 发布前 GitHub 同步已完成。确认 `yourskenny/AgentGuard` 为公开仓库, 默认分支为 `main`; 本地验证通过后将当前 HEAD 推送到 `origin/main`, 并用远端 SHA 等于本地 HEAD 作为同步验收。
- 2026-07-08: 后续 MCP adapter 对接设计已完成。新增 `docs/mcp-adapter-design.md`, 比较三种接口形态并选择保留现有窄 `ToolAdapter.execute()` port、在具体 `MCPToolAdapter` 内部隐藏 registry/session/result/error 复杂度的方案。
- 2026-07-08: 真实 MCP adapter 对接 spike 已完成。新增可选 `agentguard[mcp]` 依赖、`MCPToolAdapter`、CLI `proxy --mcp-config`、safe stdio MCP server fixture 和 gateway 集成测试; 当前全量验证为 102 passed、1 个上游 TestClient deprecation warning。
- 2026-07-08: GitHub issues/roadmap 整理已完成。创建 #1 CI workflow、#2 最小端到端 demo、#3 发布说明与录屏脚本、#4 MCP adapter 生命周期硬化四个 GitHub issues, 并新增 `docs/roadmap.md` 固化优先级和验收标准。
- 2026-07-08: CI 与发布徽章整理已完成。新增 `.github/workflows/ci.yml`, 在 push main 和 pull_request 时安装 `.[dev]` 并运行 pytest/ruff; README 增加 CI badge; roadmap 标记 GitHub #1 完成。
- 2026-07-08: 最小端到端 demo 脚本已完成。新增 `scripts/demo_e2e.py`, 一次性覆盖 scan、真实 stdio MCP adapter gateway allow、路径越界 deny、trace 读取和 85-case eval, 输出写入 `runs/demo/`; README 和 roadmap 已链接 GitHub #2。
- 2026-07-08: 发布说明和示例录屏脚本已完成。新增 `docs/release-notes.md` 和 `docs/demo-recording-script.md`, 覆盖当前里程碑、验证证据、安全边界、2-3 分钟录屏流程和禁止夸大的表述; README 和 roadmap 已链接 GitHub #3。

## 里程碑总览

| 里程碑 | 目标 | 主要产物 | 状态 |
|---|---|---|---|
| M0 | 可运行骨架 | CLI/API/模型/测试/基础 docs | 已完成 |
| M1 | MCP 配置扫描增强 | 多格式扫描、风险证据、扫描报告 | 已完成 |
| M2 | Tool Metadata Analyzer 增强 | 工具能力分类、描述注入检测、schema 风险 | 已完成 |
| M3 | Policy Engine 闭环 | allow/deny/confirm/redact 策略与测试 | 已完成 |
| M4 | Runtime Gateway 闭环 | HTTP 授权、mock 转发、trace 写入 | 已完成 |
| M5 | Replay Evaluation 闭环 | 60+ case、指标、失败样例 | 已完成 |
| M6 | 报告与展示材料 | README、报告样例、简历/面试材料 | 已完成 |

## M1: MCP 配置扫描增强

目标: `agentguard scan` 能处理更接近真实项目的 MCP 配置, 并输出 server、tool、env、command、source 和风险证据。

### M1.1 支持更多 MCP 配置结构

- [x] 支持 `mcpServers` 字典结构。
- [x] 支持 `servers` 字典结构。
- [x] 支持 `servers` 数组结构。
- [x] 支持 JSON 与 YAML 输入。
- [x] 对缺失 `command`、非法 `args`、非法 `env` 给出清晰错误。

验收标准:

- 至少 6 个 fixture 覆盖不同配置结构。
- `agentguard scan --config <fixture>` 对合法配置返回 0。
- 非法配置返回非 0, 错误信息包含具体字段名。

推荐测试:

```powershell
.\.venv\Scripts\python -m pytest tests/test_scanner.py
.\.venv\Scripts\agentguard scan --config examples\mcp.sample.json --format json
```

### M1.2 增加 server 级风险识别

- [x] 检测敏感环境变量: token、secret、password、api key、private key。
- [x] 检测危险启动命令: shell 管道、远程脚本执行、删除命令。
- [x] 检测未固定依赖来源: `npx <pkg>`、`uvx <pkg>`、无版本约束包名。
- [x] 检测高权限目录参数: home、root、磁盘根目录、`../`。

验收标准:

- 每种风险至少 2 条测试 case。
- 每条风险输出 `RiskRecord`, 包含 severity、category、evidence、recommendation。
- 扫描报告能按 server 展示风险证据。

### M1.3 扫描报告完善

- [x] Markdown 报告展示 server 总数、tool 总数、风险分布。
- [x] JSON 报告保留完整结构化字段。
- [x] SARIF 报告按风险类型生成 rules 和 results。
- [x] CLI 支持 `--output` 写文件。

验收标准:

- 三种格式都能从同一个 scan result 生成。
- Markdown 报告对人可读, JSON 报告可被测试解析, SARIF 报告符合基本 schema。

## M2: Tool Metadata Analyzer 增强

目标: 静态分析工具名称、描述、schema 和能力, 形成可解释风险画像。

### M2.1 工具能力分类

- [x] 分类 filesystem read。
- [x] 分类 filesystem write。
- [x] 分类 shell execution。
- [x] 分类 network egress。
- [x] 分类 database access。
- [x] 分类 browser automation。
- [x] 分类 credential/env access。

验收标准:

- 每类能力至少 2 条测试。
- 一个 tool 可以同时拥有多个 capability。
- capability 与风险标签分离: capability 描述能力, risk tag 描述风险。

### M2.2 描述注入检测

- [x] 检测忽略原始指令类短语。
- [x] 检测读取 secret/token/credential 类短语。
- [x] 检测外发/上传/发送敏感内容类短语。
- [x] 检测隐藏提示词、系统提示词、developer message 相关短语。
- [x] 保留匹配片段作为 evidence。

验收标准:

- 20 条 tool poisoning fixture。
- RiskRecall 在 poisoning fixture 上达到 90% 以上。
- 每个命中项都能解释为什么命中。

### M2.3 Schema 风险检测

- [x] 检测任意 `command` / `cmd` 参数。
- [x] 检测任意 `path` / `file` 参数。
- [x] 检测任意 `url` / `endpoint` / `webhook` 参数。
- [x] 检测无类型 object、additionalProperties 过宽、缺失 required。
- [x] 给 schema ambiguity 赋中风险或高风险等级。

验收标准:

- schema 风险测试不少于 15 条。
- 风险分数可解释, 不只靠单一关键字。
- 工具风险分数在 0 到 1 之间稳定输出。

## M3: Policy Engine 闭环

目标: 对真实 tool call 参数做运行时策略决策, 支持 allow、deny、confirm、redact。

### M3.1 文件系统策略

- [x] 规范化相对路径和绝对路径。
- [x] 阻断 allowed roots 之外的路径。
- [x] 阻断敏感文件名和 glob pattern。
- [x] 支持 Windows 路径和 POSIX 路径。
- [x] 对软链接逃逸风险给出策略说明。

验收标准:

- 文件策略测试不少于 20 条。
- `.env`、SSH key、pem、cookies、`../` 都被阻断。
- 合法 workspace 文件不误杀。

### M3.2 Shell 策略

- [x] 阻断删除、格式化、权限破坏类命令。
- [x] 阻断 `curl | bash`、`wget | sh`、PowerShell 远程执行。
- [x] 对任意 shell 工具默认 deny。
- [x] 将命中 pattern 写入 RiskRecord evidence。

验收标准:

- 危险命令全部 deny。
- 普通只读命令如 `pwd`、`ls` 在显式 allow 策略下可通过。
- 默认策略不允许任意 shell 执行。

### M3.3 网络外发策略

- [x] 对 POST、upload、webhook、send request 默认 confirm。
- [x] 支持域名 allowlist。
- [x] 支持阻断内网地址、metadata IP 和 localhost 外发。
- [x] 支持跨工具数据外发风险标记。

验收标准:

- 外部 URL 默认 confirm。
- allowlist 命中可 allow。
- 内网敏感地址被 deny。

### M3.4 脱敏策略

- [x] 对 key 名包含 token、secret、password、api_key 的参数脱敏。
- [x] 对 tool result 摘要执行同样脱敏。
- [x] 保留 redaction count 指标。
- [x] 避免把完整 secret 写入 trace。

验收标准:

- 脱敏测试不少于 10 条。
- trace 和报告中不出现原始 secret。
- redaction case 在 evaluator 中能统计覆盖率。

## M4: Runtime Gateway 闭环

目标: FastAPI gateway 能在工具调用前授权、阻断或确认, 并记录完整 trace。

### M4.1 API 契约落地

- [x] 实现 `/healthz`。
- [x] 实现 `/v1/tool-calls:authorize`。
- [x] 实现 `/v1/tool-calls`。
- [x] 实现 `/v1/traces`。
- [x] 实现 `/v1/runs/{run_id}/trace`。
- [x] 统一错误体, 禁止 200-with-error。

验收标准:

- 使用 FastAPI TestClient 覆盖每个 endpoint。
- deny 返回 403。
- confirm 返回 409。
- authorize 不执行 adapter。

### M4.2 Tool Adapter 抽象

- [x] 定义 adapter interface。
- [x] 实现 mock adapter。
- [x] 为后续 MCP adapter 保留接口。
- [x] 确保 deny 请求不会调用 adapter。

验收标准:

- 单测证明 deny 时 adapter call count 为 0。
- allow 时 mock adapter 返回结构化 result。
- adapter 错误被记录为 trace error event。

### M4.3 Trace Recorder 完善

- [x] 记录 policy_decision。
- [x] 记录 tool_call。
- [x] 记录 tool_result。
- [x] 记录 error。
- [x] 支持按 run_id 读取事件。
- [x] 支持参数摘要和结果摘要。

验收标准:

- 一次完整 tool call 至少产生 policy_decision 和 tool_result。
- 阻断请求产生 policy_decision, 不产生 tool_result。
- trace 不保存未脱敏 secret。

## M5: Replay Evaluation 闭环

目标: 构造足够覆盖的安全回归集, 用指标证明 AgentGuard 的策略效果。

### M5.1 扩展 JSONL Case 集

- [x] 正常工具调用 20 条。
- [x] Tool Poisoning 20 条。
- [x] 路径越界 10 条。
- [x] 敏感文件读取 10 条。
- [x] 危险 shell 命令 10 条。
- [x] 网络外发 10 条。
- [x] 跨工具组合风险 5 条。

验收标准:

- case 总数不少于 60。
- 每条 case 有 category、request、expectedDecision、expectedRiskTags。
- eval 可一次性跑完整数据集。

### M5.2 指标计算完善

- [x] RiskRecall。
- [x] FalsePositiveRate。
- [x] PolicyViolationBlockRate。
- [x] TraceCoverage。
- [x] LatencyOverhead。
- [x] RedactionCoverage。
- [x] 按 category 输出通过率。

验收标准:

- JSON 报告包含总指标和分类指标。
- 失败 case 显示 expected vs actual。
- 指标计算有单测覆盖边界情况: 空数据、全安全、全风险、混合数据。

### M5.3 回归报告样例

- [x] 生成一份 Markdown eval report。
- [x] 生成一份 JSON eval report。
- [x] 生成一份 SARIF report。
- [x] 将样例报告放入 docs 或 examples。

验收标准:

- README 能引用报告样例。
- 报告能展示风险分布和失败样例。
- SARIF 中至少包含 rule 和 result。

## M6: 展示与简历材料

目标: 让项目具备公开展示、面试讲解和简历引用条件。

### M6.1 README 完善

- [x] 写清楚项目定位: 工具安全闸门、轨迹黑盒、回放评测器。
- [x] 给出 quick start。
- [x] 展示 scan 输出样例。
- [x] 展示 eval 指标样例。
- [x] 说明非目标和安全边界。

验收标准:

- 新读者 5 分钟内能跑出 scan 和 eval。
- README 不夸大安全能力, 明确是轻量级策略网关。

### M6.2 面试讲解材料

- [x] 准备 30 秒版本。
- [x] 准备 2 分钟版本。
- [x] 准备 5 分钟架构展开版本。
- [x] 准备常见追问回答。

验收标准:

- 讲解能覆盖背景、架构、策略、trace、eval、指标。
- 能解释和业务 Agent、LangSmith/Langfuse、MCP server 自带安全机制的区别。

### M6.3 简历 bullet

- [x] 写稳健版 4 条。
- [x] 写 Agent 工程基础设施版 4 条。
- [x] 每条 bullet 对应真实已实现功能或可验证报告。
- [x] 删除未完成或无法证明的表述。

验收标准:

- 简历描述和仓库功能一致。
- 每个关键数字都有报告或测试支撑。

### M6.4 项目复盘与面试问答

- [x] 整理项目目标、边界和当前已实现证据。
- [x] 按 M0-M6 回顾每个里程碑的交付价值。
- [x] 总结关键工程取舍: local-first、规则策略、mock adapter、trace、报告。
- [x] 准备高频面试追问回答, 并明确当前不得夸大的能力边界。

验收标准:

- 新读者能从复盘文档快速定位代码、测试、报告和讲解材料。
- 面试回答能落回仓库事实, 不依赖口头包装。
- README 中有稳定入口。

## 发布前 GitHub 同步和远端验证

- [x] 确认 GitHub CLI 可用且已登录。
- [x] 确认远端仓库 `yourskenny/AgentGuard` 可访问且为 PUBLIC。
- [x] 确认远端默认分支为 `main`。
- [x] 确认当前实现分支可 fast-forward 到 `main`。
- [x] 在推送前运行 `pytest` 和 `ruff check .`。
- [x] 将当前 HEAD 推送到 `origin/main`。
- [x] 用 `git ls-remote origin main` 验证远端 main SHA 等于本地 HEAD。

验收标准:

- 公开 GitHub 仓库可访问。
- 远端默认分支包含最新 README、docs、代码、测试和报告样例。
- 本地 `git status -sb` 干净。
- 本地 HEAD 与远端 `origin/main` 的 SHA 一致。

## 后续 MCP adapter 对接设计

- [x] 明确调用方、关键操作、约束和需要隐藏的内部复杂度。
- [x] 比较极简 execute port、显式 session manager、ports-and-adapters runtime 三种接口形态。
- [x] 选择保留现有 `ToolAdapter.execute(request)` 作为 gateway 唯一依赖。
- [x] 设计具体 `MCPToolAdapter` 的 config、构造、execute、close 和错误码。
- [x] 在 README 中加入设计文档入口。

验收标准:

- 设计不改变现有 gateway policy/trace/eval 契约。
- 能指导下一步真实 MCP adapter spike。
- 错误映射、结果归一化和生命周期边界清晰。

## 真实 MCP adapter 对接 spike

- [x] 将 MCP Python SDK v1.x 加入可选 `agentguard[mcp]` 依赖和 dev extra。
- [x] 新增 `MCPToolAdapter.from_config(...)`, 从原始 MCP config 读取启动命令、参数和 env 值。
- [x] 通过 SDK `stdio_client` 和 `ClientSession.call_tool(...)` 调用 stdio MCP server。
- [x] 将 MCP result 归一化为 JSON-serializable gateway result。
- [x] 将缺失 server、缺失 serverName、SDK 调用失败、超时、非法 result 映射为稳定 `ToolAdapterError` code。
- [x] 新增 `examples/safe_mcp_server/server.py` 作为本地安全 MCP fixture。
- [x] 新增 gateway 集成测试, 证明 `/v1/tool-calls` 可通过真实 adapter 读取 `README.md`。
- [x] CLI `proxy` 支持 `--mcp-config` 启用真实 adapter, 不传则继续使用 mock adapter。

验收标准:

- 默认 mock adapter 行为不变。
- 真实 adapter 不绕过 policy: deny/confirm 仍不会执行 adapter。
- 真实 adapter 的成功和失败路径都有测试覆盖。
- pytest 和 ruff 通过。

## GitHub issues/roadmap 整理

- [x] 查询公开仓库现有 open issues, 避免重复创建。
- [x] 创建 #1: CI workflow and README status badge。
- [x] 创建 #2: minimal end-to-end demo script。
- [x] 创建 #3: release notes and demo recording script。
- [x] 创建 #4: MCP adapter session and process lifecycle hardening。
- [x] 新增 `docs/roadmap.md`, 记录优先级、issue 链接、原因和验收标准。
- [x] README 增加 Roadmap 入口。

验收标准:

- GitHub issue 与仓库文档互相引用。
- 下一步任务顺序明确。
- 每个 issue 有目标、范围和验收标准。

## CI 与发布徽章整理

- [x] 新增 GitHub Actions workflow。
- [x] workflow 覆盖 push main 和 pull_request。
- [x] workflow 安装 `.[dev]`。
- [x] workflow 运行 `python -m pytest`。
- [x] workflow 运行 `python -m ruff check .`。
- [x] README 增加 CI status badge。
- [x] roadmap 标记 GitHub #1 完成。

验收标准:

- 本地 pytest 和 ruff 通过。
- 推送后 GitHub Actions 远端 run 成功。
- GitHub #1 可关闭。

## 最小端到端 demo 脚本

- [x] 新增 `scripts/demo_e2e.py`。
- [x] demo 扫描 `examples/mcp.sample.json` 并保存 scan Markdown/JSON。
- [x] demo 通过真实 stdio MCP adapter 调用 safe server 读取 `README.md`。
- [x] demo 通过 gateway 展示路径越界 deny。
- [x] demo 读取 `demo-run` trace 并保存 JSON。
- [x] demo 跑完整 `security_cases.jsonl` eval 并保存 Markdown/JSON。
- [x] README 增加 demo 运行命令。
- [x] roadmap 标记 GitHub #2 完成。

验收标准:

- 一条命令可在已安装 `.[dev]` 的本地环境运行。
- demo 输出不包含 secret 原值。
- pytest、ruff 和 CI 通过。

## 发布说明和示例录屏脚本

- [x] 新增发布说明文档。
- [x] 新增 2-3 分钟 demo recording script。
- [x] 发布说明列出已实现能力、验证证据、安全边界和下一步。
- [x] 录屏脚本给出确切命令、预期观察和收尾口径。
- [x] 明确禁止 production、OS sandbox、enterprise traffic、hosted dashboard 等未实现表述。
- [x] README 增加入口。
- [x] roadmap 标记 GitHub #3 完成。

验收标准:

- 文档能让新读者独立完成一次项目介绍录制。
- 所有能力表述都能落回仓库当前实现和验证证据。
- pytest、ruff 和 CI 通过。

## 依赖关系

```text
M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M6
          \          \          /
           ---------->----------
```

说明:

- M1 和 M2 都服务于风险识别, M2 可以在 M1 基础上迭代。
- M3 依赖 M1/M2 的风险分类, 但可以先用当前模型独立推进。
- M4 依赖 M3 的策略决策, 但 gateway endpoint 测试可提前完善。
- M5 依赖 M3/M4 的策略与 trace 行为。
- M6 必须在 M5 有稳定指标后再写最终展示材料。

## 优先级建议

第一优先级:

- M1.1 配置结构支持。
- M1.2 server 级风险识别。
- M3.1 文件系统策略。
- M3.2 Shell 策略。
- M4.1 API 契约落地。

第二优先级:

- M2.2 描述注入检测。
- M2.3 Schema 风险检测。
- M4.2 Tool Adapter 抽象。
- M4.3 Trace Recorder 完善。
- M5.1 扩展 JSONL case。

第三优先级:

- M5.2 指标计算完善。
- M5.3 回归报告样例。
- M6 README、面试、简历材料。

## Definition of Done

一个任务只有同时满足以下条件才算完成:

- 对应代码、配置或文档已落地。
- 有单测或 CLI/API smoke 证明行为。
- 风险决策有结构化 evidence。
- README 或 docs 中能找到入口说明。
- pytest 和 ruff 通过。

一个里程碑只有同时满足以下条件才算完成:

- 该里程碑所有任务完成。
- 至少有一个端到端命令或 API 调用可以演示。
- 报告或 trace 能证明结果。
- 没有与当前架构文档冲突的行为。

## 下一步执行切片

建议下一轮从 MCP adapter 连接池与进程生命周期硬化开始, 按以下顺序做:

1. MCP adapter 连接池与进程生命周期硬化, 对应 GitHub #4。
2. 根据 CI 和 demo 结果回补 README quick start。
3. 关闭或更新已完成 GitHub issues。
4. 从 demo 输出中挑选稳定样例回补报告文档。
5. 为后续策略规则扩展增加 issue。

这 5 个切片完成后, 项目就能从“扫描结果可信”进入“运行时拦截闭环可演示”的状态。
