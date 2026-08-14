# ToyDesigner — CA-LIC 阶梯靶场 (V0-V8)

目标产品 形状的自建 licensing target：同一套程序，逐级叠加防御机制，
每级配套一个可复现攻击。代码是我们的，所以可以任意猛烈地攻击它 —
这是 CA-LIC 问题族的第一性实验台，比研究某个具体 crack 的 offset 更稳定。

## 结构

    vendor.py            厂商侧：keygen + 签发 license (Ed25519)
    license_model.py     客户端验证链 (V0..V3) + api.License 形状的模型
    app.py               启动验证 + 能力矩阵
    features/            3 种 gate 习语散布的模块 (V3 形态)
      render.py          直接布尔检查      ("This feature requires Pro license.")
      network.py         类方法 require_tier/require_pro ("Using Synchronized Outputs requires a Pro license.")
      projects.py        registry 按名导入   ("Cannot save a private toe without a Pro licence.")
    verify_baseline.py   基线：门控必须真的生效（先证明防御，再攻击）
    attacks/             V0..V3 攻击脚本
    run_all.sh           一键复现：基线 + 全部攻击

## 能力矩阵 (镜像 TD)

| feature | free | commercial | pro |
|---|---|---|---|
| render_720p | OK | OK | OK |
| render_4k | DENIED | DENIED | OK |
| shared_memory | DENIED | OK | OK |
| multi_node_sync | DENIED | DENIED | OK |
| private_toe | DENIED | DENIED | OK |

## 阶梯与实测 (2026-08-14, 本机复现)

| V | 防御机制 | 攻击 | 攻击 LOC | 需处理的 gate 位点 | 结论 |
|---|---|---|---|---|---|
| V0 | 无（plain boolean） | 改 license.json / 内存翻转 tier | 1 | 1 | 凭证伪造免费 |
| V1 | Ed25519 签名 | patch _check_signature + 加载伪造文件；或缓存翻转 | 2 | 1 | 伪造被阻，但本地检查/缓存才是真正目标 |
| V2 | + 机器绑定 (system code) | 伪造客户端自报的锚点 | 3 | 1 | 阻止了朴素复制，锚点可伪造 |
| V3 | 分散 enforcement（3 习语 × 多模块） | AST+字符串猎杀 → 逐个 patch | 5 | 4 AST / 3 字符串 | 成本随表面积增长，结构不变 |

复现：`./run_all.sh`（基线必须全 PASS，然后每个攻击必须落地）。

## 每级对应的结构教训

- V0 → 凭证伪造 = 改一个字符串/属性。
- V1 → **credential forgery resistance ≠ enforcement tamper resistance**。
  攻击者从不需要厂商私钥：本地验证是一个可以被删除的问题。
- V2 → 绑定把锚点移到"客户端自报的值"，而期望值就明文躺在 license 里。
  authority 并没有离开机器 (对应 TD 的 systemCode)。
- V3 → 表面积决定成本：找 N 个 gate 需要 ~N 次 patch；TD 里 Pro 门控字符串
  散布在引擎各处正是同一个设计。但注意：**散布只涨价，不改变结构**。

## 与 目标产品 观察的对应

| ToyDesigner | 目标产品 (核心引擎 DLL 静态观察) |
|---|---|
| tier 缓存 + 门控 | api.License.type / isPro / 各处 "requires a Pro license" |
| system code 绑定 | systemCode, "Created with different system code(5)" |
| registry gate | 集中 license 检查函数 (UT_License/UT_Protection 类) |
| 伪造 tier 文件被签名拦截 | 破解版 核心引擎 DLL 的 digest mismatch = 官方签名无法覆盖被改内容 |

## 边界声明 (诚实分层)

- Python monkeypatch 比真实二进制 patch 便宜得多：本靶标度量的是**相对成本
  结构**（位点数量、需要独立 patch 的次数），不是绝对工时。
- 未建模：反调试、混淆、完整性自检 (V4)、加密模块 (V5)、远程 entitlement
  (V6)、硬件锚点 (V7)、服务端能力 (V8) — 见 WORLD_MODEL 路线图。
- 未建模：签名以外的时间戳/吊销 (远程禁用已出现在 TD 观察中，未实现)。
- keys/ 与 runs/ 已 gitignore：厂商私钥绝不入库。

## V4-V8 authority-topology 实测

高级基线 10/10 PASS。第二阶段不再增加更多 local gate，而是改变能力、秘密与 authority 的位置：

| V | 结构 | 结果 |
|---|---|---|
| V4 | signed local integrity | 能检测篡改；local enforcement 仍可单点绕过 |
| V5 | encrypted shipped asset | free 客户端缺 key 时 patch verifier 也不能解密；Pro 收到 key 后可提取 |
| V6 | signed remote entitlement + nonce | 远端 DENY 不可伪造，但本地能力仍可在移除 local decision 后运行 |
| V7 | external/hardware-shaped primitive | 本地 fake 无法形成独立可验证 ticket；真实硬件隔离尚未证明 |
| V8 | remote capability | 客户端没有 premium implementation；本地 fake 无法形成 service-authoritative result |

关键 A/B：**remote license server != remote capability**。

复现：`./run_all.sh`。V6-V8 的 external authority 是 stdin/stdout 本地进程模拟器，不联网、不使用 Windows/KVM，也不声称提供真实硬件隔离。
