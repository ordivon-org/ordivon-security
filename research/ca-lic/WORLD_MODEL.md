# CA-LIC — Client Authority & Software Entitlement Security

问题族世界模型（v0.2, 2026-08-15；ToyDesigner V0-V8 已验证）。
结构遵循 Security 问题导向框架：objective / frontier / established /
unresolved / rejected / constraints / nextActions。

## Objective

当高价值能力已随客户端一起交付、而许可证只负责决定"你能不能调用这些
能力"时，安全边界究竟在哪里？—— 建立 Client-side Entitlement Security
的完整攻击/防御世界模型：厂商把什么交给了客户端、攻击者控制什么、
authority 移到哪里才能真正改变边界（而非只增加混淆）。

中心不变量：

    如果攻击者控制执行机器，"客户端相信自己没有权限"不能构成强安全边界。
    但并非所有客户端许可证系统一样脆弱 — 差异在于秘密与 authority 的位置。

## Frontier

- 五层分解: L0 entitlement representation / L1 verification /
  L2 enforcement / L3 asset protection / L4 external authority
- 关键区分: credential forgery resistance ≠ enforcement tamper resistance
- 待验证假说:
  - H1 same-artifact exposure: 能力实现完整存在于敌手机器 → 防御只提价
  - H2 local authority collapse: 本地程序检查本地程序 → 递归信任问题
  - H3 externalized authority: 移到攻击者不能完全控制的硬件/远程 → 真边界
  - H4 remote ≠ solved: license server ≠ remote capability；"yes, user is
    Pro"式服务器仍留本地 enforcement 问题 (replay/credential theft/API
    emulation/session theft/rollback/availability/offline semantics)
  - H5 security is economic: 目标函数从绝对防御转向 attack economics
    (Cost(attacker) + maintenance + detection + churn + expertise > value)

## Established（已建立，含证据）

1. **目标产品 7月构建 官方发行链**（隔离区 2026-08-14 观察，双工具
   链 0 分歧）: 7z-SFX → Inno 安装器 → 分卷魔数 分卷；SFX/内层安装器/
   核心引擎 DLL 均 厂商 Inc. 有效签名 + 时间戳；捆绑 加密狗 加密狗许可
   Runtime MSI。
2. **破解生态手法**: 官方 核心引擎 DLL 被 patch 后保留原签名 blob —
   digest mismatch + PE checksum 无效 (tampered-but-signed)。破解版与
   7月构建 官方构建不同 (2026-03 vs 2026-07) → 版本匹配是生态薄弱点。
3. **目标产品 entitlement 表面**: 多载体混合 (software key + systemCode 绑定 +
   加密狗许可 dongle firm/product code + 远程禁用状态 + 引擎 SDK
   challenge-response)；Pro 门控字符串散布引擎 ("This feature requires
   Pro license." / private .toe / Synchronized Outputs / OS 版本门控)；
   官方自带降级模拟钩子 app.addNonCommercialLimit。
4. **ToyDesigner V0-V3 实测**（research/ca-lic/toydesigner/）:
   签名阻伪造但本地检查可 patch；绑定阻朴素复制但锚点可伪造；
   分散 gate 成本 O(位数点) 而结构不变。基线 15/15 + 4/4 攻击落地。
5. **现实存在性证据（已脱敏）**（2026-08-14）: 同构建差分与后续兼容性观察支持一个有限结论：未授权变体改变的是客户端本地 entitlement/enforcement 语义，而不是伪造厂商签发凭证。这一观察加强了 H1/H2，但不把第三方 bypass 过程提升为 Security capability。精确 patch 位置、字节、移植工具和私有运行回执不属于公开 canonical CA-LIC。

6. **ToyDesigner V4-V8 实测**（2026-08-15，本地 Linux/self-owned；高级基线 10/10）:
   V4 完整性检测有效但 local enforcement 仍可删除；V5 free 缺 key 时本地 patch
   无法恢复明文，但授权 Pro 必须接收 key 因而存在授权后提取；V6 nonce-bound
   signed remote DENY 不能阻止本地已交付能力在 gate 被移除后运行；V7 外部必要
   primitive 与 V8 remote capability 的本地伪造都无法形成独立可验证结果。
   **最强 A/B: remote entitlement != remote capability。** V7 仅为 trust-domain
   语义模拟，不构成真实 TPM/dongle hostile-host 物理证明。

## Unresolved

- 第三方实现的内部 enforcement 结构只保留非操作性观察；除非新的防御假说确实依赖，不再扩展具体 bypass 路径
- 破解版是否带恶意载荷（未过 admission，未进 KVM）
- V7 的真实硬件 hostile-host 抵抗与 V8 的真实云服务物理/运营边界（本轮仅语义 trust-domain 模拟）
- V5 多授权用户、撤销、更新 churn 与授权后 key/asset 再分发经济学
- 现实系统对照表（JetBrains/Adobe/Windows/Denuvo/iLok/SaaS/主机/移动区）
- 目标产品 的 加密狗许可 私有组件路径的具体 enforcement 结构（静态层）

## Rejected

- 把 CA-LIC 塞进 CA1（现有工作流）—— 独立问题族
- "研究某个 crack 的 offset"作为方法 —— 退化为一版本一技巧
- 在主机上运行破解版 目标产品 —— 未知二进制按潜在恶意样本对待

## Constraints

- 全程不执行未知样本；动态验证需 KVM admission (P0 仅放行良性 fixture)
- 破解版仅作现实存在性证据，隔离区静态分析
- 不伪造厂商私钥；攻击玩具靶标而非真实产品
- 诚实分层: 已证明 / 未检出 / 不可排除，带盲区声明

## NextActions

1. [x] Phase 0 观察: 官方链验证 + tamper 证明 + entitlement 表面映射
2. [x] ToyDesigner V0-V3: plain gate / 签名 / 绑定 / 分散 enforcement
3. [x] ToyDesigner V4-V8: integrity / encrypted asset / remote entitlement / external primitive / remote capability
4. [ ] 现实系统对照表（每系统一行: 秘密在哪/authority 在哪/谁控制哪）
5. [x] 现实存在性观察已收缩为脱敏、非操作性证据；不把第三方 bypass 机制产品化或继续扩展
6. [ ] Windows/KVM 与第三方动态验证冻结；只有新的独立研究问题明确需要时再单独重开
