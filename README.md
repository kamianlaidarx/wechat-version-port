# wechat-version-port

给 Windows 微信 DLL 注入类项目（helper / AILive / wcferry 系）适配一个新的微信版本。

微信客户端每次更新都会改变内部函数地址和结构体布局，导致注入类机器人立刻失效。本 skill 提供一套**版本迁移**方法论——不是从零逆向，而是利用已有的旧版本完整映射表，重新确定新版本中每个函数的位置。

> 适用于**已有旧版本映射表**的场景。从零开始逆向一个未知程序不在本 skill 范围内。

## 安装

把整个目录复制到 skill 目录：

```powershell
# Claude Code / 兼容 harness
Copy-Item -Recurse . "$env:USERPROFILE\.agents\skills\wechat-version-port"

# 或手动创建并复制
mkdir "$env:USERPROFILE\.agents\skills"
```

目录结构必须是：

```
wechat-version-port\
  SKILL.md
  references\
    project-anatomy.md
    locating-functions.md
  scripts\
    fingerprint.py
    gen_switch.py
    sig_extract.py
    sig_scan.py
```

## 触发方式

Agent 会自动在下列场景加载：

- 「微信升级了，机器人报未适配」
- 「把微信 4.2.0.12 加进支持列表」
- 「Weixin.dll 换版本了，重新定位映射」

或显式调用：`/skill wechat-version-port`

## 内容

| 文件 | 内容 |
|---|---|
| `SKILL.md` | 三条铁律 + 七步流程 + MCP 工具映射 + 检查清单 + 失败模式速查 |
| `references/project-anatomy.md` | helper 项目的八层架构解剖（指纹登记 / 映射表 / 结构体 / 自检 / 能力集） |
| `references/locating-functions.md` | 六种函数定位方法的实际操作 |
| `scripts/fingerprint.py` | 计算 PE 指纹四元组（大小 / SHA256 / 时间戳 / 映像大小） |
| `scripts/sig_extract.py` | 提取函数特征码，自动通配 rel32 / disp32 |
| `scripts/sig_scan.py` | 扫描特征码，判断是否唯一命中 |
| `scripts/gen_switch.py` | 生成 C++ switch 骨架 + Python 测试期望表 |

## 三条铁律

1. **未验证地址一律 `return 0`**——绝不按平均偏移平移、绝不回退旧地址、绝不猜。
2. **每个能力必须实机验证**才算开放——代码写完不算。
3. **改映射必须同步改测试硬编码**——测试是映射表的第二份副本。

## 七步流程

| 步骤 | 内容 |
|---|---|
| Step 1 | 判断到底变没变（比 size + SHA256） |
| Step 2 | 登记新构建的 PE 身份（**四个地方**，不是一个） |
| Step 3 | 函数定位（全程最耗时：低地址优先 → Diaphora → 字符串 xref → 特征码 → vtable/构造函数 → 调用图） |
| Step 4 | 结构体偏移重新确认（静态硬判据：`operator new` 分配大小） |
| Step 4.5 | 运行时自检四道防线（PE 指纹 / 虚表 / 函数序言 / 指令字节） |
| Step 5 | 写映射表（业务代码必须走 `core_address()` 封装） |
| Step 6 | 能力集按版本收缩 |
| Step 7 | 测试钉死 + 实机验证 |

## 依赖

### 必装

- Python 3.8+（脚本无第三方依赖）
- Ghidra 或 IDA Pro（看函数、提特征码）

### 强烈建议

- [Diaphora](https://github.com/joxeankoret/diaphora)（IDA 插件）或 Ghidra Version Tracking —— 两版本自动比对，省 80% 时间
- x64dbg —— 动态验证结构体偏移

### 可选（MCP 后端）

- [REA](https://github.com/)（Ghidra 后端）—— `open_binary` / `procedure_pseudo_code` / `xrefs` / `analyze_function`
- seep（radare2 后端）—— 快速筛查

SKILL.md 里有完整的 MCP 调用映射和两个实测坑（含中文路径会静默降级）。

## 脚本状态

| 脚本 | 状态 |
|---|---|
| `fingerprint.py` | ✅ 已用 `notepad.exe` 实测 |
| `gen_switch.py` | ✅ 已端到端实测（含负例拦截） |
| `sig_extract.py` | ⚠️ 仅语法与参数解析验证，无真实微信 DLL 样本 |
| `sig_scan.py` | ⚠️ 同上 |

## 方法论的来源

本 skill 的架构描述基于对 [kamianlaidarx/helper](https://github.com/kamianlaidarx/helper) 三次版本适配提交的分析：

| 提交 | 内容 | 教学价值 |
|---|---|---|
| `9ff3f72` | 支持微信 4.1.15.56 | 架构范本：把散落的硬编码地址改造成映射表 + 封装 |
| `1d40bc1` | 支持微信 4.2.0.11 | 加版本模板：17 个文件的改动清单 |
| `3e65e4b` | 4.2 好友和群事件 | 验证的必要性：代码写完 26 分钟就发现漏了功能 |

**已知局限**：仓库只包含适配结果，不包含分析过程（原作者明确说明逆向数据库、调试器、跟踪日志不入库）。因此部分细节是从 diff 反推的，SKILL.md 中已标注哪些是实证、哪些是推断。

## 风险提醒

- Windows 微信 DLL 注入违反微信用户协议，**有封号风险**。
- 适配失败时可能导致微信崩溃，建议在测试账号上验证。
- 本 skill 只包含方法论与工具，不包含任何微信客户端文件或绕过手段。
- helper 项目本身采用个人非商业许可，使用时请遵守其条款。

## License

MIT（仅限本 skill 的文档与脚本）
