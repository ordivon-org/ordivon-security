# CA-LIC — Client Authority & Software Entitlement Security

问题族世界模型（草稿 v0.1, 2026-08-14）。
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

1. **目标产品 2025. 官方发行链**（隔离区 2026-08-14 观察，双工具
   链 0 分歧）: 7z-SFX → Inno 安装器 → 驱动工具 分卷；SFX/内层安装器/
   核心库.dll 均 厂商. 有效签名 + 时间戳；捆绑 厂商 授权服务
   Runtime MSI。
2. **破解生态手法**: 官方 核心库.dll 被 patch 后保留原签名 blob —
   digest mismatch + PE checksum 无效 (tampered-but-signed)。破解版与
    官方构建不同 (2026-03 vs 2026-07) → 版本匹配是生态薄弱点。
3. **TD entitlement 表面**: 多载体混合 (software key + systemCode 绑定 +
   授权服务 dongle firm/product code + 远程禁用状态 + 目标产品引擎
   challenge-response)；Pro 门控字符串散布引擎 ("This feature requires
   Pro license." / private .toe / Synchronized Outputs / OS 版本门控)；
   官方自带降级模拟钩子 app.addNonCommercialLimit。
4. **ToyDesigner V0-V3 实测**（research/ca-lic/toydesigner/）:
   签名阻伪造但本地检查可 patch；绑定阻朴素复制但锚点可伪造；
   分散 gate 成本 O(位数点) 而结构不变。基线 15/15 + 4/4 攻击落地。
5. **真实 crack patch 定位 + 7月移植**（2026-08-14, 官方 2025. 同构建
   diff, 隔离区 ANALYSIS_REPORT.md 追加3-4）: 破解基底 = 2025.; 3 区
   5 编辑: ①授权服务 gate (0x181279e40) 恒真 — 23 调用点单一咽喉
   ②license-state 查询 (fcn.…) 强制返回 4 = Pro 级别 (关键!)
   ③状态机跳块 ④⑤quit 消息双 NOP。.data/.rdata 零改动 → 绕过型确认
   (非 keygen)。** 移植成功并经真机验证 Pro 可用**: 5 编辑同构
   重定位 (gate 0x1812871c0 / license-state fcn.… / 状态机
   0x181dd4303 / quit 0x1817912b1+bf), 工具 patch_td_.py +
   verify_port.py; 教训: gate 恒真仅保证启动 (v1 实测 NC), license-state
   恒 4 才是 Pro 判定关键 (初判 tail 为死代码属误判, 零 E8 调用者
   ≠ 不可达 — 经空列表路径被调用)。

## Unresolved

- 破解 核心库.dll 的 5 处编辑的上游触发条件与状态码语义（静态已定位,
  动态确认 pending; 见 Established 5）
- 破解版是否带恶意载荷（未过 admission，未进 KVM）
- V4-V8 各级的实测成本曲线（完整性/加密模块/远程/硬件/服务端能力）
- 现实系统对照表（JetBrains/Adobe/Windows/Denuvo/iLok/SaaS/主机/移动区）
- TD 的 授权服务 私有组件路径的具体 enforcement 结构（静态层）

## Rejected

- 把 CA-LIC 塞进 CA1（现有工作流）—— 独立问题族
- "研究某个 crack 的 offset"作为方法 —— 退化为一版本一技巧
- 在主机上运行破解版 TD —— 未知二进制按潜在恶意样本对待

## Constraints

- 全程不执行未知样本；动态验证需 KVM admission (P0 仅放行良性 fixture)
- 破解版仅作现实存在性证据，隔离区静态分析
- 不伪造厂商私钥；攻击玩具靶标而非真实产品
- 诚实分层: 已证明 / 未检出 / 不可排除，带盲区声明

## NextActions

1. [x] Phase 0 观察: 官方链验证 + tamper 证明 + entitlement 表面映射
2. [x] ToyDesigner V0-V3: plain gate / 签名 / 绑定 / 分散 enforcement
3. [ ] ToyDesigner V4-V6: integrity / encrypted module / remote entitlement
4. [ ] 现实系统对照表（每系统一行: 秘密在哪/authority 在哪/谁控制哪）
5. [x] r2 定位破解 核心库.dll 的 license gate patch（2026-08-14 完成:
    同构建 diff, 3 区 5 编辑, 见 Established 5）
6. [ ] KVM admission 流程为破解版申请动态验证（若用户决定）
