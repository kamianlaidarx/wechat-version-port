---
name: wechat-version-port
description: 给 Windows 微信 DLL 注入类项目（helper / AILive / wcferry 系）适配一个新的微信版本。当微信升级导致机器人报「未适配」「未知构建」「指纹不匹配」，或想把新版微信加进支持列表时使用。覆盖指纹登记、RVA 映射重定位、结构体偏移修正、能力集收缩、测试钉死、实机验证六个环节。适用于已有旧版本完整映射表的「版本迁移」场景，不适用于从零逆向。
---

# 微信版本迁移（version porting）

## 这个 skill 解决什么

微信每次大版本更新，`Weixin.dll` 里被 hook 的函数地址全部变化。现有项目（helper 等）用**精确指纹 + 硬编码 RVA 映射表**工作，微信一变就失效。

本 skill 的流程是**版本迁移**，不是从零逆向：你已有旧版本的完整答案（哪个 RVA 是什么函数、结构体什么布局），新版本只需重新对一遍地址。

工作量差别：从零逆向 3–6 个月，版本迁移 3 天–3 周。

## 三条铁律

1. **未验证的地址一律 `return 0`，绝不按「平均偏移量」平移猜测。**
   猜错了不崩溃、只发错内容或脏写内存，线上跑一周才暴露，且无法定位。
2. **每个能力必须实机验证才算适配完成。**
   代码能编译、测试全绿 ≠ 能用。helper 作者适配 4.2.0.11 后 26 分钟才发现漏了好友和群事件。
3. **改映射表必须同步改测试里的硬编码期望值。**
   测试是唯一能拦住「改错一位数」的防线，因为 C++ 里 `case 0x2fb010: return 0x311990;` 写错编译不报错。

---

## 前置检查

### 工具（用 pwsh 逐条验证）

```powershell
# IDA Pro 或 Ghidra（二选一，IDA 优先）
Get-ChildItem "C:\Program Files\IDA*","D:\IDA*" -ErrorAction SilentlyContinue
Get-ChildItem D:\tools\ghidra* -ErrorAction SilentlyContinue

# 可选但强烈推荐：Diaphora（IDA 插件）或 Ghidra Version Tracking
Get-ChildItem "$env:APPDATA\Hex-Rays\IDA Pro\plugins\diaphora*" -ErrorAction SilentlyContinue

# x64dbg
Get-ChildItem "C:\Program Files\x64dbg","D:\tools\x64dbg" -ErrorAction SilentlyContinue

# Python 侧
py -3.13 -c "import pefile, capstone; print(pefile.__version__, capstone.__version__)"
```

缺 capstone / pefile 就装：
```powershell
py -3.13 -m pip install pefile capstone -i https://mirrors.cloud.tencent.com/pypi/simple
```

### 确认目标版本

```powershell
# 当前微信版本
(Get-Item "C:\Program Files\Tencent\Weixin\Weixin.exe").VersionInfo.FileVersion
# 核心 DLL 位置（4.x 在 Weixin\版本号\Weixin.dll）
Get-ChildItem "C:\Program Files\Tencent\Weixin" -Recurse -Filter Weixin.dll | Select-Object FullName, Length
```

### 确认项目侧支持状态

```powershell
Get-Content C:\helper-main\native\compatibility.json -Encoding UTF8
```

如果新版本已在列表里 → 不用适配，直接查 README 的能力范围。

---

## Step 1　判断到底变没变

微信升级不等于核心逻辑变。先算指纹。

```powershell
py -3.13 "$env:USERPROFILE\.agents\skills\wechat-version-port\scripts\fingerprint.py" "C:\Program Files\Tencent\Weixin\4.x.x\Weixin.dll"
```

输出 JSON：
```json
{
  "path": "...",
  "size": 205929008,
  "sha256": "745cdf29...",
  "pe_timestamp": "0x6ae0a8d1",
  "image_size": "0xc4dc000",
  "image_base": "0x140000000",
  "machine": "x64",
  "version_hint": "4.2.0.11"
}
```

**判据**：`size` 和 `sha256` 与项目 `compatibility.json` 里任一条完全一致 → 该版本已支持，停。
不一致 → 进入 Step 2。

---

## Step 2　登记新构建的 PE 身份

### 要登记的是四个地方，不是两个

这是最容易漏的一步。漏了任何一处，要么注入被拒（好），要么运行时崩溃（坏）。

| # | 文件 | 记什么 | 谁读 |
|---|---|---|---|
| 1 | `native/compatibility.json` | 版本号 + 架构 + `Weixin.dll` 大小 + SHA256 | Python 侧 |
| 2 | `native/core_version.h` 的 `core_builds[]` | 大小 + SHA256前32字节 + **PE TimeDateStamp** + **SizeOfImage** | 原生端 |
| 3 | `native/run_selftest.py` | 核对 **`Weixin.exe` 的 FileVersion** + 调 `compatible_core()` 匹配白名单 | 自检脚本 |
| 4 | `wxbot_framework/native_profiles.py` 的 `CORE_PROFILES` | Python 侧**只读账号发现**用的最小 profile | Python 侧 |

**注意 #2 和 #3 核的是不同文件**：
- `core_builds[]` 核 `Weixin.dll`（hook 目标）
- `run_selftest.py` 还要核 `Weixin.exe` 的 FileVersion（启动器）

两个文件的版本号可能不一致（微信偶尔出现 exe 已更新、dll 未更新），所以都要核。

### 为什么记四元组而不只是 SHA256

```json
{
  "wechat_version": "4.2.0.11",
  "architecture": "x64",
  "size": 205929008,
  "sha256": "745cdf2955fa5128cdb00c056c97571156a5f107406a9bb15ac0754f3246b201"
}
```

C++ 侧 `native/core_version.h`：

```cpp
{3, 205929008ull, 0x6ae0a8d1, 0xc4dc000, {0x74,0x5c,0xdf,...}}
// id 文件大小   PE时间戳   映像大小   SHA256前32字节
```

- **SHA256** 校验磁盘文件
- **PE 时间戳 + 映像大小**校验**内存里已加载的映像**

有人把 DLL 打完补丁再运行，磁盘 SHA 就变了，但内存映像的 PE 头仍是原版特征。原生端加载后会再核一次已加载映像，是第二道关。

### id 分配

`id` 是 profile 编号，后续所有 `switch (profile->id)` 靠它分流。**新增版本一定要分配全新 id，不要复用**——复用会导致旧分支被误命中。

已用编号（helper 项目）：`1` = 4.1.15.13，`2` = 4.1.15.56，`3` = 4.2.0.11。新增从 `4` 开始。

---

## MCP 工具映射（不手动开 IDA 也能干活）

本机已注册两个逆向 MCP，能覆盖大部分静态分析动作。**能用 MCP 就别开 GUI**，结果可复制、可复现。

### rea（Ghidra 后端）

| 任务 | 工具调用 |
|---|---|
| 打开目标 | `rea.open_binary(path="D:\\work\\Weixin.dll", provider_id="ghidra")` |
| 段/节布局、ImageBase、入口 | `rea.inspect_binary_layout(path=...)` |
| 按名字搜函数 | `rea.search_procedures(pattern="SendText", mode="literal")` |
| 列全部函数 | `rea.list_procedures()` |
| 反编译 | `rea.procedure_pseudo_code(procedure="0x311990")` |
| 反汇编 | `rea.procedure_assembly(procedure="0x311990")` |
| 单条指令解码 | `rea.inspect_native_instruction(address="0x311990")` |
| 交叉引用 | `rea.xrefs(address="0x311990")` |
| 按符号名查引用 | `rea.find_xrefs_to_name(name="...")` |
| 调用图 | `rea.get_call_graph(address="0x311990", direction="forward")` |
| 调用路径 | `rea.trace_call_path(start="0x311990", goal="0x...")` |
| 函数体分析 | `rea.analyze_function(procedure="0x311990")` |
| 批量反编译对比 | `rea.batch_decompile(addresses=[...])` |
| 两函数差异 | `rea.compare_functions(left=..., right=...)` |
| 读原始字节 | `rea.read_bytes(address="0x311990", length=64)` |
| 收尾 | `rea.close_binary()` |

### seep（radare2 后端，适合快速筛查）

| 任务 | 工具调用 |
|---|---|
| 一键体检（架构/加固/字符串） | `seep.seep_auto_triage(target_path=...)` |
| 函数列表 | `seep.seep_r2_functions(binary_path=..., filter_name="Send")` |
| 反编译（可控 token） | `seep.seep_r2_decompile(binary_path=..., target="0x311990", output_mode="summary")` |
| 反汇编（只看分支） | `seep.seep_r2_disasm(binary_path=..., target="0x311990", output_mode="branch")` |
| 交叉引用 | `seep.seep_r2_xrefs(binary_path=..., target="0x311990", direction="to")` |
| 任意 r2 命令 | `seep.seep_r2_cmd(binary_path=..., command="afl~Send")` |

### 两个实测坑（务必遵守）

1. **含中文的路径会让 seep 静默降级**
   `seep_auto_triage` / `seep_r2_info` 遇到中文路径会返回 `arch=unknown`、`format=unknown`、字符串采样为空，**不报错**。先把目标复制成纯 ASCII 路径再调：
   ```powershell
   Copy-Item "D:\微信分析\Weixin.dll" "D:\work\wx42011\Weixin.dll"
   ```

2. **rea 的 provider 选择要显式**
   不指定 `provider_id` 会走 auto，可能选到不适合 DLL 的后端。分析 PE 时显式写 `provider_id="ghidra"`。

### MCP 能做什么、不能做什么

| 能做 | 不能做 |
|---|---|
| 反编译、反汇编、查 xref、跟调用图 | 自动两个版本比对（Diaphora 那种） |
| 按名字/地址找函数 | 动态调试（要看运行时内存得用 x64dbg） |
| 读任意地址字节 | 搜索字节模式（用 `sig_scan.py`） |

**结论**：Diaphora 那一档的自动化比对靠 GUI 工具；单点定位和验证几乎全能用 MCP 完成。

---

## Step 3　函数定位（全程最耗时的一步）

### 3.1 先把旧表摸清

```powershell
Get-Content C:\helper-main\native\core_version.h -Encoding UTF8 | Select-String -Pattern "case 0x"
```

得到形如 `case 0x2fb010: return 0x311990;` 的完整列表。

**先数清楚有多少条**——已知的实测数字：

| 版本 | 映射条数 | 备注 |
|---|---|---|
| 4.1.15.56 | 55 条 | 这次适配的主要工作是把硬编码地址改造成映射表 |
| 4.2.0.11 | 首次 40 条 + 26 分钟后补 5 条 = 45 条 | 补的是好友验证 `VerifyUser` 链路：`0x754330`、`0x1a26440` 等 |

朋友圈另有独立映射表（地址体系不同），条数单独统计。

### 3.1.5 先确认「不会变的那批」（重要提速技巧）

**低地址的基础库函数通常跨版本不变。**

helper 项目里已经确认长期稳定的一批：

```
0x7a60    基础工具
0x45d10   基础工具
0x88ad0   基础工具
0x2010    基础工具
```

**做法**：拿到新 DLL 后，先跳到这几个低地址，比对函数开头几个字节。如果一致（大概率一致），这几条映射直接写 `case 0x7a60: return 0x7a60;`，跳过所有定位工作。

一次适配里这类「地址没动」的条目往往占 30–50%，先干掉它们能把工作量砍一半。

**判据**：函数大小相同 + 前 32 字节完全相同 → 认定为未变。任一条不满足就老老实实定位。

### 3.2 方法 A：Diaphora 自动比对（首选，省 80% 时间）

```
1. IDA 打开旧版 Weixin.dll → 等分析完 → File > Produce file > Create DIF
2. IDA 打开新版 Weixin.dll → 等分析完 → Diaphora > Diff database
3. 选旧库的 .sqlite
4. 结果按 similarity 排序，>0.95 的基本可直接采信
```

Ghidra 替代：`Tools > Version Tracking`，两个 program 建 session，跑 correlators。

**能自动对上的直接抄地址，对不上的才进 3.3。**

### 3.3 方法 B：特征码扫描（最通用）

从旧函数头部提机器码，通配掉会随版本变的部分。

```powershell
# 用 capstone 提取并自动通配
py -3.13 "$env:USERPROFILE\.agents\skills\wechat-version-port\scripts\sig_extract.py" `
  --dll "C:\path\old\Weixin.dll" --rva 0x2fb010 --len 48

# 输出: 48 89 5C 24 08 55 56 57 41 54 48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ??
```

再在新版里搜：

```powershell
py -3.13 "$env:USERPROFILE\.agents\skills\wechat-version-port\scripts\sig_scan.py" `
  --dll "C:\path\new\Weixin.dll" --pattern "48 89 5C 24 08 55 56 57 41 54 48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ??"
```

**合格判据：命中数必须恰好为 1。**

- 命中 0 → 特征段被优化了，加长特征（往函数内部多取 32 字节），或换方法 C
- 命中 > 1 → 特征太短，加长或换更靠后的指令段

自动通配规则（`sig_extract.py` 已实现）：
| 指令类型 | 通配原因 |
|---|---|
| `call rel32` / `jmp rel32` | 目标地址变了 |
| RIP 相对寻址 `[rip+disp32]` | 全局变量位置变了 |
| 绝对立即数（指针类） | 同上 |
| `mov reg, imm32` 的普通常量 | **不要通配**，这是有效特征 |

### 3.4 方法 C：字符串交叉引用（最稳）

字符串内容几乎不随版本改，是定位黄金锚点。

```powershell
# 1. 旧版本：找到函数引用了哪个字符串
#    IDA: 跳函数 → 找 lea rax, aXxx → 双击看内容

# 2. 新版本：全局搜该字符串
#    IDA: Alt+B 或 Search > Immediate，输入字符串片段

# 3. 看 xref，找到引用它的函数 = 同一函数的新地址
```

适合：发消息（"发送失败"）、撤回（"撤回了一条消息"）、朋友圈（URL 常量）。

### 3.4.5 方法 C2：vtable → RTTI → 构造函数

**适用于**：目标是 C++ 类的成员函数，或者要定位「创建某类对象的工厂函数」。

helper 项目里工厂函数 `0x6f4c70` 就是这么找到的。

#### 步骤

**情况 1：已知旧函数，求新地址**

```
1. 旧版本：看旧函数属于哪个类（IDA 里 xref 到 vtable，或看 this 指针用法）
2. 找到该类的 vtable 地址（旧版本）
3. 找 vtable 里的某个函数指针在磁盘上的 RVA
4. 新版本：搜这个 RVA 值的字节序列（小端 8 字节）
   → 命中处就是新版本的 vtable 位置（vtable 里存的是绝对地址或 RVA）
5. 从新 vtable 取对应槽位的函数指针 = 新地址
```

**情况 2：要定位工厂函数**

工厂函数（`CreateXxx` / `MakeXxx`）的特征：调用 `operator new` 分配对象 → 往对象头部写 vtable 指针 → 返回。

```
1. 找到目标类的 vtable RVA（新版）
2. 搜「写这个 vtable 地址到 [reg]」的指令序列：
   lea rax, [rip+<vtable>]
   mov [rbx], rax          ← 把 vtable 写进对象第一个字段
3. 该指令所在函数 = 构造函数
4. 构造函数的调用者中，有 operator new 的那个 = 工厂函数
```

#### 为什么这条最可靠

vtable 里的函数指针集合是类的「指纹」——一个类的虚函数数量、顺序在版本间几乎不变，只有地址变。通过 vtable 反查比通过代码特征找类成员可靠得多。

#### 项目里怎么记这些链

`native/friend_request.h` 的注释直接记录了调用链：

```
// 1780cd0 → 754330 → 1a26440 → 1a17980
```

**建议照做**：定位过程中把所有「已知 A 调用 B」的链记在头文件注释里，下次适配直接复用，不用重新捋。

### 3.5 方法 D：调用图回溯

已知调用链 A→B→C，只丢了 B：

1. 用 A/B 的任一方法定位 A 和 C
2. 在 A 的反汇编里找 `call`，逐个跳到候选函数
3. 在 C 的反汇编里找调用者（IDA: 函数上 Ctrl+X）
4. 两个结果取交集 = B

朋友圈那一族地址（`core_moments_address()` 的 15 条）基本只能这样一节节捋出来。

### 3.6 定位结果落表

```powershell
# 生成 C++ switch 骨架 + Python 测试期望表，避免手抄出错
py -3.13 "$env:USERPROFILE\.agents\skills\wechat-version-port\scripts\gen_switch.py" `
  --in pairs.json --profile-id 3 --out-dir .
```

`pairs.json` 格式：
```json
{"text": {"0x2fb010": "0x311990", "0x6f4c70": "0x71c4e0"},
 "moments": {"0x44776d0": "0x4538550"}}
```

输出两个文件：`core_rva_switch.txt`（贴进 `core_version.h`）和 `test_expected.py`（贴进测试）。

---

## Step 4　结构体偏移重新确认

**这一步错了最致命**：不崩溃，只发错内容。

### 4.1 静态硬判据（首选，不用跑起来）

**不要靠「读内存看值是否合理」这种软判断**，有个更硬的锚点：**构造函数里 `operator new` 的分配大小**。

#### 判据一：对象分配大小

```
1. 找到目标类的构造函数（用 3.4.5 的 vtable 法）
2. 看它调用 operator new 时传的大小常量
3. 与旧版本比对
```

helper 的实测例子（`moments_send.h`）：

| 版本 | 朋友圈发布对象大小 |
|---|---|
| 4.1.15.56 | `0x2b8` |
| 4.2.0.11 | `0x2c8` |

**差 `0x10`** → 结构体变大了 16 字节 → 字段整体后移 `0x10`。

#### 判据二：构造函数里各字段的写入偏移

```
1. 在构造函数反汇编里，找所有写操作：mov [reg+偏移], 值
2. 列出「偏移 → 写入的值/来源」
3. 与旧版本的表对比
```

- 所有偏移**统一 + 同一个值** → 头部插了字段，套统一位移
- 部分偏移**变化量不同** → 中间插了字段，逐字段换算
- 偏移**完全一致** → 布局没变

#### 判据三：跨版本偏移可能不变的部分

**不是所有结构体都会变。** helper 的实测：

| 结构 | 4.1.15.56 | 4.2.0.11 | 结论 |
|---|---|---|---|
| 朋友圈发布对象 | `0x2b8` | `0x2c8` | 变了，+0x10 |
| 语音 `ImgBuf` 偏移 | `+0x30` / `+0x10` | `+0x30` / `+0x10` | **没变** |

`text_bridge.cpp:317` 里直接改成 `profile >= 2`，说明「4.1.15.56 和 4.2 的语音布局相同」。

**所以先做静态比对，再决定要不要写 `model_field()` 这类补偿函数。** 盲目给所有结构体加偏移修正，会把本来对的地方改错。

### 4.2 动态验证（静态判断有疑问时）

在 x64dbg 里：

1. 断在任一个已知函数入口
2. 读出对象指针
3. 按旧偏移读，看是不是合理值（消息类型 1/3/34/43/49、字符串指针、长度字段）
4. 不合理就扫 `[base, base+0x400]` 找正确偏移

### 4.3 代码写法

```cpp
static size_t model_field(size_t offset) {
    return offset + (core_profile_id == 3 ? 0x10 : 0);
}
// 所有 model + 0x30 / 0x248 / 0x60 / 0x118 / 0x40 / 0x280 / 0x84
// 改成 model + model_field(0x30) 等
```

### 4.4 找不到偏移时的扫描法

```python
# 在 [base, base+0x400] 范围内找符合预期的值
for off in range(0, 0x400, 8):
    val = read_u64(base + off)
    if 1 <= val <= 50:          # 候选消息类型
        print(hex(off), val)
```

---

## Step 4.5　运行时自检（四道防线）

**这一步我最初漏了，是整份 skill 里最容易出人命的缺口。**

映射写对了 ≠ 运行时一定对。可能的情况：地址定位对但偏移错、对象还没初始化就 hook、微信内部状态不同导致对象布局不同。

helper 项目在**三个层面**做运行时自检，出问题时**拒绝执行而不是硬闯**。

### 防线 1：虚表校验

对象创建出来后，比对它的 vtable RVA 是否等于预期值。

```cpp
// selftest_bridge.cpp:291
if (*(uint64_t*)object != core_base + core_rva(0x8e53588)) {
    return false;   // 对象类型不对，拒绝继续
}
```

**作用**：确认「这个对象确实是我以为的那个类」。地址定位错了、或 hook 到了别的函数，这里就会失败。

**为什么用 vtable 而不是别的**：vtable 指针是对象的第一个字段，读起来最稳；且每个类的 vtable 地址唯一。

### 防线 2：函数序言字节比对

```cpp
// moments_send.h
static bool anchors_match(const uint8_t* fn) {
    // 比对目标函数开头 16 个字节
    return memcmp(fn, expected_prologue, 16) == 0;
}
```

**作用**：确认「我要 hook 的这个函数，确实是我以为的那个函数」。

和 Step 2 的指纹校验不同：指纹校验的是**整个 DLL**，这里校验的是**单个函数**。DLL 指纹过了但映射表某条写错，这道防线能拦住。

### 防线 3：指令字节比对

`wxbot_framework/native_profiles.py` 里检查 getter 是否正好是：

```
48 8d 41 48 c3      lea rax, [rcx+48h]; ret
```

**作用**：确认「这个函数的实现细节没变」。

比防线 2 更严格——不只看开头，而是看**完整的关键指令**。适合「知道自己要找的是哪种具体操作」的场景（比如「取某字段的 getter 一定长这样」）。

### 防线 4：双读一致性

指针链读两次，确认结果一致（防止读到正在被 GC / 正在修改的对象）。

### 四道防线各拦什么

| 防线 | 拦什么 | 检查对象 |
|---|---|---|
| PE 指纹（Step 2） | 换了个微信版本没适配 | 整个 DLL |
| 虚表校验 | 对象类型认错 | 运行时对象 |
| 函数序言 | 映射表某条地址写错 | 单个函数 |
| 指令字节 | 函数内部实现变了 | 单个函数的关键指令 |
| 双读一致性 | 读到竞态中的脏数据 | 指针链 |

**结论：静态定位完 ≠ 完事，运行时每一层都要兜底。**

---

## Step 5　写映射表（未验证一律拒绝）

### 5.1 映射表本身

```cpp
if (profile->id == 3) {
    switch (legacy) {
        case 0x178f100: return 0x17cf210;   // 发消息
        case 0x2fb010:  return 0x311990;
        // ... 40 条首次 + 5 条补漏
        default: return 0;      // ← 关键：未登记的地址返回 0，不回退到旧地址
    }
}
```

`default: return 0` 的语义是「这个功能我没验证过，拒绝执行」，不是「大概差不多」。

**注意注释里写了 `default` 的两个错误替代**：

```cpp
// ✗ 错误 1：回退到旧地址
default: return legacy;
// 跳到一个在旧版本才有效的位置，新版里可能是别的函数中间

// ✗ 错误 2：按平均偏移平移
default: return legacy + 0x1a000;
// 微信新版本不是均匀插入代码，是「删几个 + 加几十个 + 重排」
```

### 5.2 业务代码必须走封装，禁止直接算地址

**这是 helper 项目的一个硬约束，我第一次漏了。**

业务代码里**不允许**写：

```cpp
// ✗ 禁止
void* fn = core_base + 0x178f100;

// ✓ 必须
void* fn = core_address(core_base, 0x178f100);
```

`core_address()` 内部调 `core_rva()`，接受 `legacy` 编号、返回本版本的实际地址、未登记时返回 `nullptr`。

**为什么这条重要**：

- 直接算地址 = 绕过映射表 = 新版本上必然错，且错误位置和真实原因无关
- 走封装 = 未适配的功能**统一在 `core_address()` 返回 `nullptr` 这一处暴露**，好排查

4.1.15.56 那次适配的主要工作，就是**把所有硬编码地址改成 `core_address()` 调用**，把多版本框架搭起来。之后每出新版本只需补一张映射表。

### 5.3 用测试禁止硬编码

`tests/test_native_version_bridge.py` 里有正则检查：

```python
def test_no_hardcoded_core_address_arithmetic(self):
    for path in native_sources():
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"core_base\s*\+\s*0x", text), \
            f"{path} 存在 core_base + 0x... 硬编码"
```

**这条测试的价值**：以后任何人图方便写了一次硬编码，CI 立刻红。人的记忆力靠不住，靠测试。

### 5.4 配套：注入前预检

```python
# native/run_selftest.py
if build.get('wechat_version') == '4.2.0.11':
    unsupported = (
        mode not in ('--listen','--remove','--dispatch','--download-image','--download-file')
        or any(v is not None for v in (emoticon_path, group_operation, friend_request))
    )
    if unsupported:
        raise RuntimeError('微信 4.2.0.11 此功能尚未适配')
```

**在 `VirtualAllocEx` 之前就抛错**，比注入后发现地址错、微信崩了强得多。

---

## Step 6　能力集按版本收缩

### 6.1 后端声明能力

`wxbot_framework/backend.py`：

```python
TEXT_42011_CAPABILITIES = CAPABILITIES | frozenset({
    "friend.text.receive", "friend.text.send",
    "group.text.receive", "group.text.send", "group.text.mention",
    "group.members.read", "message.recall",
    "image.receive", "image.send", "file.receive", "file.send",
    "voice.receive", "voice.send",
})

@property
def capabilities(self):
    if self.raw.wechat_version == '4.2.0.11':
        return TEXT_42011_CAPABILITIES
    return CAPABILITIES
```

### 6.2 框架按能力过滤插件

`wxbot_framework/runtime.py` 的 `_connect()`：

```python
capabilities = getattr(candidate, 'capabilities', None)
if isinstance(capabilities, (set, frozenset)) and frozenset(capabilities) != self.plugins.capabilities:
    self.plugins.capabilities = frozenset(capabilities)
    for name, record in tuple(self.plugins.records.items()):
        if record.spec.requires - self.plugins.capabilities:
            self.plugins.disable(name, persist=False)
    self.plugins.reload()
```

**注意 `_connect()` 里要有消息暂存门**：收信线程可能在 `start()` 返回前就收到消息，此时能力集还没更新，插件会用错能力处理。

### 6.3 插件侧声明依赖

```python
class VoiceReplyPlugin(Plugin):
    requires = frozenset({"voice.send"})
```

没声明 `requires` 的插件默认在所有版本加载，所以**新版本不支持某能力时，一定要给相关插件补上 `requires`**。

---

## Step 7　测试钉死 + 实机验证

### 7.1 硬编码期望值

`tests/test_native_version_bridge.py`：

```python
VERIFIED_TEXT_42011 = {0x2010:0x2010, ..., 0x2fb010:0x311990, ...}
VERIFIED_MOMENTS_42011 = {0x44776d0:0x4538550, ...}

def test_native_mapping_is_exact_verified_set_and_has_no_duplicate_case(self):
    for block, expected in ((new_block, VERIFIED_TEXT_42011), (old_block, VERIFIED_RVAS)):
        rows = re.findall(r"case\s+(0x[0-9a-f]+):\s*return\s+(0x[0-9a-f]+);", block)
        self.assertEqual(len(rows), len(expected))
        self.assertEqual(len({old for old, _ in rows}), len(rows))   # 查重复 case
        self.assertEqual({int(old,16):int(new,16) for old,new in rows}, expected)
```

第三行查重复 case 很重要：C++ `switch` 里两个 case 值相同时，**前一个被静默忽略**，复制粘贴漏改就会踩。

### 7.2 断言注入前拒绝

```python
def test_42011_unsupported_operation_is_rejected_before_injection(self):
    with patch('native.bridge.VirtualAllocEx') as alloc, \
         patch('native.bridge.remote_call') as call:
        with self.assertRaises(RuntimeError):
            self.bridge.start(emoticon_path='x.png')
        alloc.assert_not_called()
        call.assert_not_called()
```

### 7.3 跑测试

```powershell
cd C:\helper-main
.\venv\Scripts\python.exe tools\run_tests.py
.\venv\Scripts\python.exe tools\run_tests.py --pattern test_native_version_bridge.py --verbose
```

⚠️ 测试用临时文件和模拟后端，**不启动真实机器人、不注入微信、不发真消息**。全绿只证明代码自洽，不证明能用。

### 7.4 实机验证清单（逐项打勾，缺一不算完成）

| # | 功能 | 验证方法 | 通过标准 |
|---|---|---|---|
| 1 | 账号识别 | 启动 `main.py` | 打印 `机器人账号已绑定：昵称 \| 微信ID=wxid_xxx` |
| 2 | 文本接收 | 手机给文件传输助手发 `echo 你好` | 收到回复「你好」 |
| 3 | 会话 ID | 发 `test` | 收到会话 ID |
| 4 | 群文本接收 | 群里 @机器人 说话 | 机器人回复 |
| 5 | 群艾特识别 | 群里 @ 而非普通消息 | 只有 @ 才触发 |
| 6 | 文本发送 | 长文本 500 字 | 分段发出、顺序正确 |
| 7 | 图片接收 | 好友发图 | 日志有图、能下载 |
| 8 | 图片发送 | 触发发图插件 | 对方收到 |
| 9 | 文件接收 | 好友发文件 | 能下载 |
| 10 | 文件发送 | 触发发文件 | 对方收到 |
| 11 | 语音接收 | 好友发语音 | 能下载（如需转文字再看） |
| 12 | 语音发送 | 触发 TTS 回复 | 对方听到 |
| 13 | 撤回通知 | 好友撤回消息 | 防撤回插件补发 |
| 14 | 好友申请 | 小号加机器人 | 日志有记录 |
| 15 | 群成员进群 | 小号进群 | 日志有记录 |
| 16 | 朋友圈读取 | 网页面板点朋友圈 | 列出动态 |
| 17 | 朋友圈发布 | 发一条仅自己可见 | 发布成功 |

**4.2.0.11 作者实测时第 14、15 项是事后补的**——这就是为什么清单要逐项打勾而不是「感觉跑通了」。

---

## 检查清单（提交前自检）

### 指纹登记（4 处，缺一不可）

- [ ] `native/compatibility.json` 加了新版本条目（版本号 + 架构 + 大小 + SHA256）
- [ ] `native/core_version.h` 的 `core_builds[]` 加了 `CoreBuild`（id + 大小 + SHA256前32字节 + PE 时间戳 + 映像大小）
- [ ] `native/run_selftest.py` 能识别新版本（核对 `Weixin.exe` FileVersion + `compatible_core()`）
- [ ] `wxbot_framework/native_profiles.py` 的 `CORE_PROFILES` 加了最小只读 profile

### 地址映射

- [ ] `core_rva()` 新增 profile 分支，`default: return 0` 保留
- [ ] 朋友圈地址单独走 `core_moments_address()`
- [ ] 映射条数与旧版本对齐（漏一条 = 一个功能挂）
- [ ] **业务代码全部走 `core_address(core_base, legacy)`，无 `core_base + 0x` 硬编码**
- [ ] 有测试用正则禁止硬编码地址算术

### 结构体偏移

- [ ] 确认过是「整体平移」还是「逐字段变」（看构造函数里 `operator new` 的大小 + 字段写入偏移）
- [ ] 确认过哪些结构体**没变**（不要盲目给所有结构体加偏移修正）
- [ ] 需要补偿的用 `model_field()` 之类包装，不散落各处

### 运行时自检（四道防线）

- [ ] 虚表校验（对象 vtable RVA 比对）
- [ ] 函数序言字节比对（16 字节）
- [ ] 关键指令字节比对（适用于有明确实现特征的操作）
- [ ] 双读一致性（指针链读两次）

### 能力与降级

- [ ] `backend.py` 新增 `*_CAPABILITIES`，`scope` 和 `capabilities` 改成 `@property`
- [ ] `runtime.py` 能力门控 + 消息暂存门
- [ ] `run_selftest.py` 注入前预检（在 `VirtualAllocEx` 之前抛错）
- [ ] 受影响插件补 `requires`

### 验证与文档

- [ ] 测试里硬编码新期望值（独立冻结表，不从生产代码推导）
- [ ] `tools/run_tests.py` 全绿
- [ ] 实机验证清单 17 项打勾
- [ ] `native/README.md` 更新已适配/未支持功能
- [ ] 顶层 README 更新支持版本字符串
- [ ] `docs/` 里的功能范围同步

---

## 失败模式速查

| 现象 | 原因 | 处理 |
|---|---|---|
| 启动报「未知构建」 | 指纹没登记或四元组不匹配 | 重跑 fingerprint.py，确认记的是 `Weixin.dll` 而非 `Weixin.exe` |
| 启动报「消息桥接尚未适配」 | `core_rva()` 返回 0 | 检查 switch 是否漏了这个 legacy 地址 |
| 注入成功但收不到消息 | 收信函数地址错 | 用字符串 xref 重定位接收函数 |
| 发出去是乱码/空消息 | 结构体偏移错 | Step 4 重做，别套统一位移 |
| 微信随机崩溃 | 映射到了错的函数，脏写内存 | 回滚该条映射为 `return 0`，重新定位 |
| 测试红但功能正常 | 改了代码没改测试期望值 | 同步更新 `VERIFIED_*` 字典 |
| 插件加载了但不工作 | 缺 `requires` 声明 | 补能力依赖 |

---

## 参考

- `references/project-anatomy.md` — helper 项目五层架构完整解剖，每条对应源码位置
- `references/locating-functions.md` — 四种定位方法的具体 IDA/Ghidra 操作步骤
- `scripts/fingerprint.py` — PE 指纹四元组
- `scripts/sig_extract.py` — 提特征码并自动通配
- `scripts/sig_scan.py` — 在新 DLL 扫特征码
- `scripts/gen_switch.py` — 生成 switch 代码 + 测试期望表

## 研究路径（三次提交按序看，最容易懂）

helper 项目有三次与版本适配直接相关的提交。**按时间顺序看**，思路最清楚：

```powershell
cd C:\helper-main
git log --oneline --all | Select-String "4.1.15.56|4.2.0.11|4.2"

# 第一次：把框架搭起来（55 条映射 + core_address 封装）
git show 9ff3f72 -- native/

# 第二次：4.2.0.11 首次适配（40 条）
git show 1d40bc1 -- native/

# 第三次：26 分钟后的补漏（5 条，好友验证链路）
git show 3e65e4b -- native/
```

### 每次提交看什么

| 提交 | 看什么 |
|---|---|
| `9ff3f72`（4.1.15.56） | 「怎么把硬编码改造成多版本框架」——这是架构范本 |
| `1d40bc1`（4.2.0.11） | 「有了框架后，加一个版本具体要动哪些文件」——14 个文件的改动 |
| `3e65e4b`（4.2 补充） | 「实测发现漏了什么」——验证清单为什么必须逐项打勾 |

**`1d40bc1` 到 `3e65e4b` 只隔 26 分钟**，这是最有教育意义的时间差：适配写完到发现漏了好友和群事件，中间只有 26 分钟。说明**代码写完 ≠ 功能能用**。

### 练习方法

1. 本机拿到新旧两个 `Weixin.dll`
2. 挑 `0x178f100`（发消息）这类特征明确的函数
3. 用 Diaphora / BinDiff 自己定位一遍
4. 和仓库里的映射对答案

**对上了说明方法对，对不上说明特征选得不好。**

---

## 风险提醒（必须知道）

1. **微信用户协议禁止第三方客户端/外挂。** 注入 hook 的账号**有被封风险**，尤其是新注册账号、异地登录、行为异常的账号。

2. **建议练习用小号**，机器人账号和主号分离。

3. **helper 项目许可是「仅限个人非商业使用」。** 不要拿去卖服务或做商业产品。

4. **不要在客户环境 / 生产环境测试未验证的映射。** 映射错了可能导致微信崩溃，如果这个微信绑着重要业务，损失是自己承担。

5. **适配失败的回退**：把该条映射改回 `return 0` 即可降级为「该功能不可用」，不影响其他功能。这是 `default: return 0` 设计的实际价值。

---

## 硬提醒（部署时）

本项目是**精确指纹绑定**。微信自动更新到 4.2.0.12 或 4.2.1，机器人立刻失效。

部署时必须关掉微信自动更新，或把更新程序改名：

```powershell
Get-ChildItem "C:\Program Files\Tencent\Weixin" -Recurse -Filter "*Update*.exe" |
  ForEach-Object { Rename-Item $_.FullName ($_.Name + ".disabled") }
```
