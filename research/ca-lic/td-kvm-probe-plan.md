# 目标产品 license probe plan (KVM 动态验证)

Case: research/cases/windows-kvm-p1-目标产品-case-a-execution.json

## 运行实证 (2026-08-14, 三次迭代)

1. **拼写陷阱**: guest-runner 读 ordivon-run.json (i), 驱动曾写 ordovon-* (o)
   → ItemNotFoundException。已修。
2. **只读 USB NTFS 不自动挂载**: readonly=on usb-storage 挂载 9.6GB NTFS,
   Win11 guest 120s 内 Get-Volume 找不到 ORDIVON_P1_EXEC 卷; 改 writable
   挂载立即找到。实证: P1 只读媒体从未在真实 guest 验证过。
   → 运行使用 --writable-exec-media (operator-directed 偏差);
     媒体完整性由 pre/post digest 保护 (材料化 manifest 记录 pre-digest,
     运行后 re-hash 对比)。
3. **runner 版本漂移**: bundle 内 runner.exe 是旧版 (a0a804fa),
   驱动 fixture 用新版 (b53e6636) → 契约 installer digest 不匹配。
   已同步 td-src + 重打包 + 重建 manifest + 重材料化。

## 两阶段结构 (operator-directed 2026-08-14)

- **阶段一 (KVM, deny-all 网络)**: 无病毒判定 + license 状态/效验点动态定位。
  残余不销毁 (operator 覆盖 closure 策略) — 媒体/VM 状态保留给阶段二。
- **阶段二 (真实 Windows + GPU, host)**: 阶段一 verdict 干净后, 用户在
  真实机器上用 GPU 实测 Pro 功能 (render 4K / 同步输出 / private toe)。
  这是机器所有者的自决; 破解 DLL 仅在阶段一全绿后视为 clean。
  阶段二产出 = "实际使用层面"的最终答案。

## 阶段一无病毒证据链 (verdict 输入)

1. 静态审查 (已完成): 官方树全链签名有效; 破解 DLL = Derivative 原版二进制
   + license 相关修改, 无可疑字符串/导入/外联痕迹
2. ClamAV (freshclam 更新后): 破解 DLL + 官方安装器 + 官方 核心库
3. KVM 行为: 进程/文件/注册表/网络全插桩, 无恶意行为 (下载器/持久化/外联)
4. 诚实边界: 以上 = "无恶意行为证据", 非"绝对无病毒" (加密载荷不可排除,
   但破解 DLL 来源已知 = Derivative 引擎, 风险面有界)

## 目标 (双重)

1. **判定破解是否有效**: A/B (对照官方无 key / 实验破解 DLL) → license 状态差值
2. **动态定位效验点**: 插桩调用栈 → 效验函数 RVA 列表 + A/B 行为分叉点 +
   license 全局地址 → 静态 xref 收尾成完整效验点地图 (反转"先静态后动态"
   顺序 — 静态已因无锚点卡住, 动态给的 RVA 就是新锚点)

## 探针信号 (按优先级)

0. **插桩层 (双重目标的关键)** — Procmon + API Monitor, 命令行模式
   (headless 兼容, 日志到文件):
   - 追踪: CreateFile(ins*.dat/密钥文件.txt), RegOpenKeyEx/RegQueryValueEx,
     LoadLibrary(授权服务/厂商), GetSystemTimeAsFileTime, VirtualProtect
   - **每个 license 相关调用点捕获调用栈** → 栈内返回地址 = 效验函数 RVA
     (动态定位, 绕过静态字符串零引用墙)
   - A/B 两轮同插桩 → 行为首次分叉点 = patch 生效位置
   - 输出 = 效验点地图 (RVA 列表) → 静态 xref 收尾成完整调用图
1. **TD Python API (主信号)** — 探针 .toe + execute DAT:
   - app.product ("目标产品 Pro" / "Commercial" / "Non-Commercial")
   - td.licenses: 每个 license 的 type / status / systemCode / version
   - lic.isPro() / isNonCommercial()
   - Pro 门控实测: 创建 private COMP + root.save(.toe) →
     期望非 Pro 时抛 "Cannot save a private toe without a Pro licence."
   - 输出 JSON 到 run 盘 (控制器可提取位置)
2. **注册表 (独立信号)** — observer 前后 diff:
   - licenceAccess.exe (纯 ADVAPI32) 域 = TD 注册表 license 状态
   - 读 HKCU/HKLM Software\Derivative 相关键 (键路径以实测为准)
3. **进程/文件行为** — 无 UI 环境下的生存信号:
   - TD 是否启动并存活 (崩溃 = 版本错配/ABI 破坏 → 直接证据)
   - WerFault 崩溃转储存在性
   - 日志/错误消息: "Checking 授权服务 Licenses", "Deactivated after
     failing to initialise correctly", "Unrecognized key format"
   - 密钥文件行为: 密钥文件.txt / ins*.dat 的创建/读取痕迹
4. **UI 水印** — 无 display 设备, 不做 (VM 设计无显示器)

## 探针 .toe 构建 (无 TD 环境)

- 官方工具链: toeexpand (.toe→目录, DAT 成 .py 文本) → 编辑注入探针
  Python → toecollapse (目录→.toe)
- 若 toeexpand/toecollapse 本身需要 license (author 工具), 备选:
  手工构造最小 .toe (二进制格式, 需逆向) 或改用信号 2+3 为主

## Guest 执行流程 (每轮)

1. 密封基座快照 → 附加只读媒体 (官方树 + 破解 DLL + 探针 + 控制器)
2. 部署: 复制官方树到 C:\Program Files\Derivative\目标产品\
   (文件树部署, 不经安装器 — 实验对象是 DLL 行为, 不是安装器)
3. 对照组: 原样启动 目标产品.exe + 探针 → 收集 JSON/注册表/日志
4. 实验组: 替换 核心库.dll → 重复
5. 证据导出 + 快照还原 + 残余关闭

## 风险与盲区

- **GPU**: guest 无 GPU passthrough, TD 需 D3D11 (WARP 软渲染不确定)。
  第 1 轮先建立 "TD 能否启动" 事实; 启动失败本身也是证据
  (破解 DLL 与 7月组件 ABI 错配 → 崩溃)。
- 网络 deny-all: TD 在线激活路径不可达 → 测试的是离线 license 行为
  (这正是本地密钥/破解生效场景)。
- 无显示器: UI 水印/对话框不可见 → 依赖文件/注册表/进程信号。
