# helper 项目五层架构解剖

以 `kamianlaidarx/helper` 的三次适配提交（`9ff3f72` 4.1.15.56 / `1d40bc1` 4.2.0.11 / `3e65e4b` 补漏）为样本，逐层拆出「一个微信版本要接进来，需要改哪些地方」。

**结论先行**：新版本接入 = 6 个必改层 + 测试钉死。少一层都会在运行时炸。

```
1. 指纹白名单      4 处登记（compatibility.json / core_builds[] / run_selftest.py / CORE_PROFILES）
2. RVA 映射表      core_rva() + core_moments_address()，未登记一律 return 0
3. 结构体偏移      model_field()，但先确认哪些结构体其实没变
4. 能力集收缩      backend.py 的 *_CAPABILITIES + 插件 requires
5. 运行时门控      runtime.py 消息暂存 + run_selftest.py 注入前预检
5.5 运行时自检     虚表 / 函数序言 / 指令字节 / 双读，四道防线
6. 测试钉死        独立冻结表，不从生产代码推导
```

---

## 第 0 层：项目结构速查

```
C:\helper-main\
├─ main.py                  控制台入口
├─ web.py                   网页管理台（127.0.0.1:8765）
├─ start_web.bat
├─ requirements.txt         只有 4 个依赖
├─ bot_config.json          ┐
├─ members_config.json      │ 4 个配置，init_config.py 生成，
├─ llm_config.json         │ 网页可编辑，更新时会被覆盖（先备份）
├─ tts_config.json         ┘
├─ native\                  ← C++ 桥接层，版本适配的主战场
│  ├─ core_version.h        ① 版本指纹 + RVA 映射表
│  ├─ compatibility.json    ① 指纹白名单（Python 侧也读）
│  ├─ text_bridge.cpp       ③ 消息收发实现
│  ├─ build\text_bridge.dll     预编译产物
│  ├─ build_text\text_bridge.dll 预编译产物
│  ├─ selftest_bridge.dll
│  ├─ run_selftest.py       ⑤ 注入前预检
│  └─ vendor\               MinHook
├─ wxbot_framework\         ← Python 层
│  ├─ backend.py            ④ 后端与能力集
│  ├─ runtime.py            ⑤ 运行时门控
│  ├─ native_profiles.py    ② 地址子集
│  ├─ startup.py            账号扫描
│  ├─ contacts.py           联系人
│  ├─ moments_reader.py     朋友圈读取
│  └─ moments_interaction_transport.py  朋友圈互动
├─ plugins\                 各功能插件
├─ tests\
│  └─ test_native_version_bridge.py   ⑥ 映射表钉死
└─ tools\
   ├─ init_config.py
   └─ run_tests.py
```

---

## 第 1 层：指纹白名单

**作用**：加载任何东西之前，先确认「这是不是我知道的那个微信」。

### `native/compatibility.json`

```json
[
  {
    "wechat_version": "4.1.15.13",
    "architecture": "x64",
    "size": 201552944,
    "sha256": "10f8e995..."
  },
  {
    "wechat_version": "4.1.15.56",
    "architecture": "x64",
    "size": 204305968,
    "sha256": "e0428a7b..."
  },
  {
    "wechat_version": "4.2.0.11",
    "architecture": "x64",
    "size": 205929008,
    "sha256": "745cdf2955fa5128cdb00c056c97571156a5f107406a9bb15ac0754f3246b201"
  }
]
```

### `native/core_version.h` 的 `CoreBuild`

```cpp
struct CoreBuild {
    int id;                  // profile 编号，switch 用它分支
    unsigned long long size; // 文件字节数
    unsigned int pe_timestamp;
    unsigned int image_size;
    unsigned char sha256_prefix[32];
};

static constexpr CoreBuild core_builds[] = {
    {1, 201552944ull, 0x..., 0x..., {0x10,...}},   // 4.1.15.13
    {2, 204305968ull, 0x..., 0x..., {0xe0,...}},   // 4.1.15.56
    {3, 205929008ull, 0x6ae0a8d1, 0xc4dc000, {0x74,0x5c,0xdf,...}},  // 4.2.0.11
};
```

**为什么要四元组而不只是 SHA256**：

- SHA256 校验的是**磁盘文件**
- PE 时间戳 + 映像大小校验的是**内存里已加载的映像**
- 有人把 DLL 打完补丁再运行，磁盘 SHA 就变了，但内存映像的 PE 头仍是原版特征

原生端 `WxStartTextReceiver` 里会再核一次已加载映像，两道关。

**为什么要 `id`**：后续所有 `switch (profile->id)` 靠它分流。新版本必须分配**全新 id**，复用会导致旧分支被误命中。

### `native/run_selftest.py` —— 第三个登记点（容易漏）

```python
# 核 Weixin.exe 的 FileVersion，再用 compatible_core() 匹配 Weixin.dll 白名单
build = compatible_core(dll_path)
if build is None:
    raise RuntimeError("未知构建")
```

**注意这里核的是 `Weixin.exe`，和前面核 `Weixin.dll` 不同。** 微信偶尔出现「exe 已更新、dll 未更新」或反过来，两个文件都要核。

### `wxbot_framework/native_profiles.py` 的 `CORE_PROFILES` —— 第四个登记点

Python 侧做**只读账号发现**（不注入、只读内存）时用的最小 profile：

```python
CORE_PROFILES = {
    "4.1.15.13": {...},
    "4.1.15.56": {...},
    "4.2.0.11":  {...},
}
```

`native_profiles.py` 里的 getter 还带指令字节校验（见第 5.5 层防线 3）。

**为什么单独一份**：账号发现只需要读 wxid，不需要完整的 55 条映射。分开维护能降低耦合——桥接不适配时，至少账号还能认出来（对应第 5 层的 `ACCOUNT_DISCOVERY_PROFILES`）。

---

## 第 2 层：RVA 映射表

**这是适配工作的核心产出。**

### 文本/媒体/群缓存 → `core_rva()`

```cpp
static unsigned long long core_rva(unsigned long long legacy) {
    if (profile->id == 1 || profile->id == 2) {
        // 4.1.x 直接用原地址
        return legacy;
    }
    if (profile->id == 3) {
        switch (legacy) {
            case 0x2fb010:  return 0x311990;
            case 0x6f4c70:  return 0x71c4e0;
            case 0x178f100: return 0x17cf210;   // 发消息
            // ... 首次 40 条 + 26 分钟后补 5 条 = 45 条
            default: return 0;   // ← 未验证即拒绝
        }
    }
    return 0;
}
```

**实测条数**：

| 版本 | 条数 | 说明 |
|---|---|---|
| 4.1.15.56 | 55 | 这次适配同时把硬编码改造成映射表 |
| 4.2.0.11 | 40（首提）+ 5（补漏）= 45 | 补的是好友验证 `VerifyUser` 链路：`0x754330`、`0x1a26440`、`0x1a17980` 等 |

### 业务代码必须走 `core_address()` 封装

```cpp
// ✗ 禁止：绕过映射表
void* fn = core_base + 0x178f100;

// ✓ 必须：走封装
void* fn = core_address(core_base, 0x178f100);
```

`core_address()` 接受 `legacy` 编号，返回本版本实际地址，**未登记时返回 `nullptr`**。

**这条约束的实际价值**：未适配的功能统一在 `core_address()` 一处返回空，排查时只需要在一个地方下断点。如果各写各的 `core_base + 0x...`，错误会散布在几十个位置。

**4.1.15.56 那次适配的主要工作就是这件事**——把已有的硬编码地址全部改造成 `core_address()` 调用，把多版本框架搭起来。之后每出新版本只需补一张映射表。

`tests/test_native_version_bridge.py` 用正则禁止回退：

```python
def test_no_hardcoded_core_address_arithmetic(self):
    for path in native_sources():
        assert not re.search(r"core_base\s*\+\s*0x", path.read_text(encoding="utf-8"))
```

### 朋友圈 → `core_moments_address()`（单独一张表）

朋友圈的地址体系和主逻辑不同（走另一套 RPC/接口），所以**必须单独一张表**：

```cpp
static unsigned long long core_moments_address(unsigned long long legacy) {
    if (profile->id == 3) {
        switch (legacy) {
            case 0x44776d0: return 0x4538550;
            // ... 共 15 条
            default: return 0;
        }
    }
    return legacy;
}
```

**Python 侧对应**（`wxbot_framework/native_profiles.py`）：

```python
_TEXT_42011_RVAS = {
    # 只列账号识别 / 缓存 / 表情地址的子集，共 11 条
}

# 4.2.0.11 不开放表情，所以掩码为空
emoticon_cache_mask = b""
```

### `default: return 0` 为什么是设计而不是偷懒

对比错误做法：

```cpp
// ✗ 错误：按平均偏移平移
default: return legacy + 0x1a000;
```

微信新版本不是均匀插入代码，是「删几个函数 + 加几十个函数 + 重排」。平均偏移对某些函数凑巧对，对另一些就是**跳到别的函数中间**，调用即崩，且崩溃地址和真实原因无关，极难排查。

`return 0` 的语义是「我没验证过这个功能」，上层据此拒绝执行并给用户明确提示。

---

## 第 3 层：结构体偏移

**4.2.0.11 的 model 结构体整体平移 +0x10。**

```cpp
static size_t model_field(size_t offset) {
    return offset + (profile->id == 3 ? 0x10 : 0);
}
```

所有访问点改写：

| 原写法 | 新写法 |
|---|---|
| `model + 0x30` | `model + model_field(0x30)` |
| `model + 0x248` | `model + model_field(0x248)` |
| `model + 0x60` | `model + model_field(0x60)` |
| `model + 0x118` | `model + model_field(0x118)` |
| `model + 0x40` | `model + model_field(0x40)` |
| `model + 0x280` | `model + model_field(0x280)` |
| `model + 0x84` | `model + model_field(0x84)` |

**为什么统一位移有效**：微信在 model 结构体头部插了 16 字节（很可能是新的字段或 vtable 槽），后面所有字段整体后移。这种情况套统一位移是对的。

**什么时候不能套**：
- 微信在**中间**插字段 → 前半段不变，后半段变，必须逐字段确认
- 某字段类型变了（`int32` → `int64`）→ 后面的偏移按类型大小累加变化

**判断方法**：x64dbg 里用旧偏移读，看是不是合理值。合理 → 该偏移没变；不合理 → 扫范围找。

---

## 第 4 层：能力集按版本收缩

### 后端侧（`wxbot_framework/backend.py`）

```python
TEXT_42011_CAPABILITIES = CAPABILITIES | frozenset({
    "friend.text.receive", "friend.text.send",
    "group.text.receive", "group.text.send",
    "group.text.mention",
    "group.members.read",
    "message.recall",
    "image.receive", "image.send",
    "file.receive", "file.send",
    "voice.receive", "voice.send",
})


class NativeTextBackend:
    @property
    def scope(self):
        if self.raw.wechat_version == "4.2.0.11":
            return "文本、语音、图片及文件收发，群艾特、文字撤回和群成员缓存"
        return "文本、图片与文件收发；语音、表情发送；好友申请与控制台群管理"

    @property
    def capabilities(self):
        if self.raw.wechat_version == "4.2.0.11":
            return TEXT_42011_CAPABILITIES
        return CAPABILITIES
```

**关键**：`scope` 和 `capabilities` 从类属性改成 `@property`，因为要按实例版本动态返回。

### 插件侧声明依赖

```python
class VoiceReplyPlugin(Plugin):
    requires = frozenset({"voice.send"})
```

没声明 `requires` 的插件会在所有版本加载，**给新版本不支持的插件补上 `requires` 是必做项**。

---

## 第 5 层：运行时门控 + 注入前预检

### 运行时门控（`wxbot_framework/runtime.py`）

```python
def _connect(self):
    # ... 启动 backend ...
    capabilities = getattr(candidate, "capabilities", None)
    if isinstance(capabilities, (set, frozenset)) and \
       frozenset(capabilities) != self.plugins.capabilities:
        self.plugins.capabilities = frozenset(capabilities)
        for name, record in tuple(self.plugins.records.items()):
            if record.spec.requires - self.plugins.capabilities:
                self.plugins.disable(name, persist=False)
        self.plugins.reload()
```

**消息暂存门**：`start()` 返回前，收信线程可能已经开始收消息。此时能力集还没更新完，若直接派发，插件会用错能力。所以要在门控完成前把消息暂存。

### 注入前预检（`native/run_selftest.py`）

```python
if build.get("wechat_version") == "4.2.0.11":
    unsupported = (
        mode not in ("--listen", "--remove", "--dispatch",
                     "--download-image", "--download-file")
        or any(v is not None for v in (emoticon_path, group_operation, friend_request))
    )
    if unsupported:
        raise RuntimeError("微信 4.2.0.11 此功能尚未适配")
```

**为什么必须在注入前**：

- 注入后才发现地址错 → 微信进程崩溃 → 用户以为程序坏了
- 注入前抛 `RuntimeError` → 干净的 Python 异常 → 用户知道是版本不支持

### 账号扫描降级（`wxbot_framework/startup.py`）

```python
# 有些构建只能识别账号，桥接还没适配
ACCOUNT_DISCOVERY_PROFILES = ()   # 单独列出，不混进桥接白名单

def scan_logged_accounts(...):
    ...
    if not any(a.bridge_supported for a in accounts):
        raise RuntimeError("当前微信版本仅支持账号识别，消息桥接尚未适配，暂不能启动机器人")
```

**这是好设计**：账号识别（读 wxid）和消息桥接（hook 收发）难度差一个量级。先支持前者，用户至少能看到「程序认出了你的号」，知道方向没错。

---

---

## 第 5.5 层：运行时自检（三道防线）

**这一层是防崩溃的最后屏障。** 静态定位再准，运行时对象布局也可能不同——尤其是对象还没完全初始化就被 hook 的情况。

### 防线 1：虚表校验

```cpp
// selftest_bridge.cpp:291
if (*(uint64_t*)object != core_base + core_rva(0x8e53588)) {
    return false;   // 对象类型不对，拒绝继续
}
```

**拦什么**：hook 到了错的函数、拿到了错的对象、地址定位整体偏移。

**为什么用 vtable**：vtable 指针是对象的第一个字段（offset 0），读起来最稳；每个类的 vtable 地址唯一，比对成本低。

**注意 `0x8e53588` 本身也在映射表里**——vtable 地址也会随版本变。

### 防线 2：函数序言字节比对

```cpp
// moments_send.h
static bool anchors_match(const uint8_t* fn) {
    return memcmp(fn, expected_prologue, 16) == 0;
}
```

**拦什么**：映射表里某一条地址写错了（跳到了别的函数）。

**为什么和 Step 2 的指纹校验不重复**：

| 校验 | 粒度 | 能拦 |
|---|---|---|
| PE 指纹（第 1 层） | 整个 DLL | 换版本没适配 |
| 函数序言（本层） | 单个函数 | **某一条映射写错** |

DLL 指纹过了，不代表 45 条映射条条都对。这层是逐条兜底。

### 防线 3：指令字节比对

```python
# wxbot_framework/native_profiles.py
# 检查 getter 是否正好是 lea rax,[rcx+48h]; ret
INSTRUCTION_CHECK = bytes.fromhex("488d4148c3")
```

**拦什么**：函数地址对，但内部实现变了（比如字段偏移变了，getter 从 `[rcx+48h]` 变成了 `[rcx+58h]`）。

**比防线 2 更严格**：不只看开头，而是看**完整的关键指令**。适用于「明确知道要找的是哪种操作」的场景。

### 防线 4：双读一致性

指针链读两次，确认结果相同。

**拦什么**：读到正在被 GC / 正在被修改的对象（竞态）。

### 四道防线的关系

```
PE 指纹      → 整个 DLL 是我认识的那个版本吗？
    ↓ 通过
虚表校验      → 这个运行时对象是我以为的那个类吗？
    ↓ 通过
函数序言      → 这个函数的地址对吗？
    ↓ 通过
指令字节      → 这个函数的实现细节对吗？
    ↓ 通过
双读一致性    → 读到的数据是稳定的吗？
```

**任意一关不过就拒绝执行**，而不是带着不确定状态硬跑。

---

## 第 6 层：测试钉死

`tests/test_native_version_bridge.py`：

```python
VERIFIED_RVAS = {0x2010: 0x2010, 0x45d10: 0x45d10, ...}          # 4.1.15.56
VERIFIED_TEXT_42011 = {0x2010: 0x2010, 0x2fb010: 0x311990, ...}  # 4.2.0.11
VERIFIED_MOMENTS_42011 = {0x44776d0: 0x4538550, ...}

def test_native_mapping_is_exact_verified_set_and_has_no_duplicate_case(self):
    for block, expected in ((new_block, VERIFIED_TEXT_42011),
                            (old_block, VERIFIED_RVAS)):
        rows = re.findall(r"case\s+(0x[0-9a-f]+):\s*return\s+(0x[0-9a-f]+);", block)
        self.assertEqual(len(rows), len(expected))
        self.assertEqual(len({old for old, _ in rows}), len(rows))   # 查重复
        self.assertEqual({int(old, 16): int(new, 16) for old, new in rows}, expected)
```

### 三条断言的各自作用

| 断言 | 拦住什么 |
|---|---|
| `len(rows) == len(expected)` | 漏写或多写一条 |
| `len({old...}) == len(rows)` | 复制粘贴漏改，两个 case 值相同（C++ 会静默忽略前一个） |
| `dict == expected` | 某条地址改错一位 |

### 还有断言「注入前拒绝」

```python
def test_42011_unsupported_operation_is_rejected_before_injection(self):
    with patch("native.bridge.VirtualAllocEx") as alloc, \
         patch("native.bridge.remote_call") as call:
        with self.assertRaises(RuntimeError):
            self.bridge.start(emoticon_path="x.png")
        alloc.assert_not_called()
        call.assert_not_called()
```

**`alloc.assert_not_called()` 是核心**：证明拒绝发生在注入之前，不是注入后才发现。

---

## 附：4.2.0.11 适配的全部改动清单（从 diff 反推）

按文件列出，可作为「新版本适配要动哪些文件」的模板。

| 文件 | 改动 |
|---|---|
| `native/compatibility.json` | 新增四元组 |
| `native/core_version.h` | 新增 `CoreBuild`；`core_rva()` 分支 **40+5 条**；`core_moments_address()` 分支；`model_field()` |
| `native/text_bridge.cpp` | `copy_voice_message` 里 `profile_id == 2` → `>= 2`（4.2 语音布局与 4.1.15.56 相同）；`WxStartTextReceiver` 里 4.2 跳过 `friend_receive_start()` |
| `native/selftest_bridge.cpp` | **虚表校验** `core_rva(0x8e53588)` |
| `native/moments_send.h` | `model_field()`；`anchors_match()` **函数序言 16 字节比对**；分配大小 **0x2b8 → 0x2c8** |
| `native/friend_request.h` | 补 5 条 VerifyUser 链路映射（`0x754330` / `0x1a26440` / `0x1a17980`） |
| `native/run_selftest.py` | 注入前预检；**核 `Weixin.exe` FileVersion** |
| `native/README.md` | 更新已适配/未支持功能表 |
| `wxbot_framework/backend.py` | 新增 `TEXT_42011_CAPABILITIES`；`scope`/`capabilities` 改 `@property` |
| `wxbot_framework/runtime.py` | 能力门控 + 消息暂存 |
| `wxbot_framework/native_profiles.py` | **`CORE_PROFILES` 新增条目**；`_TEXT_42011_RVAS`（11 条子集）；`emoticon_cache_mask = b""`；**getter 指令字节校验** |
| `wxbot_framework/startup.py` | `bridge_supported=False` 支持 |
| `wxbot_framework/contacts.py` | `read_contact_name` 加 `CONTACT_CACHE_VTABLE_RVA not in profile.rvas` 判断 |
| `wxbot_framework/moments_reader.py` | `_SOURCE_TABLES` 加 4.2.0.11 两条虚表地址；`_decode` 跳过 `gh_` 广告 |
| `wxbot_framework/moments_interaction_transport.py` | `version != '4.1.15.56'` 时 preflight 失败（4.2 不开放点赞评论） |
| `tests/test_native_version_bridge.py` | `VERIFIED_RVAS` / `VERIFIED_TEXT_42011` / `VERIFIED_MOMENTS_42011`；查重复 case；**禁硬编码地址算术的正则测试** |
| `README.md` | 支持版本字符串 |

**数一下：17 个文件。** 这就是一个版本的完整适配工作量。

**其中真正需要「逆向」的只有四个**：`core_version.h`（映射表）、`moments_send.h`（结构体布局）、`friend_request.h`（补漏链路）、`native_profiles.py`（账号发现子集）。**其他 13 个都是纯工程改动**——把新版本接进已有的框架里。

---

## 一个反面观察

`native/README.md` 里 4.2.0.11 的「已实测」清单很长（账号识别、文字收发、群消息与真实艾特、撤回通知、好友申请接收与通过、成员进退群提醒、文件传输助手图片/文件/语音发送、私聊图片/文件/语音接收和撤回补发、朋友圈读取与发布），但「未开放」也明确列了四项（联系人扫描、表情包、群管理、朋友圈点赞评论）。

**这个对比本身就是方法论**：适配时不要追求「全部支持」，先把最常用的链路打通、逐条实测、明确标出边界。用户知道边界在哪，就不会在踩坑时误以为是 bug。
