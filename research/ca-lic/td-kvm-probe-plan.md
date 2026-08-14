# 目标产品 license probe plan (KVM 动态验证)

Case: research/cases/windows-kvm-p1-目标产品-case-a-execution.json

## 目标

A/B 判定破解 核心库.dll 是否真的解锁 Pro：
- 对照组: 官方树 + 无 key → 记录 license 状态 (期望 NC/free)
- 实验组: 换破解 核心库.dll → 记录 license 状态 + Pro 功能探针
- 差值 = 破解真实行为 (Pro 解锁 / NC 会话限制 / 无效)

## 探针信号 (按优先级)

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
