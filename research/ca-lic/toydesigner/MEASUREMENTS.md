# ToyDesigner 实测记录 — 2026-08-14

复现命令: `./run_all.sh`（基线先全 PASS，再跑 4 个攻击）

## 基线（门控必须先真的生效）

15/15 PASS（free/commercial/pro × 5 特性），另加：
- 伪造 tier 翻转 → `signature invalid: InvalidSignature` 拒绝 ✓

## V0 — plain boolean gate

    [ATTACK A] edited license.json tier -> pro : 4K render OK
    [ATTACK B] runtime tier flip              : 4K render OK
    MEAS v0 plain_flip sites=1 loc=1
    结论: 凭证伪造成本 = 改一个 JSON 字符串 / 一个属性写

## V1 — Ed25519 签名

    [FORGERY] tier flipped in file -> REJECTED (signature invalid)
    [PATCH] _check_signature -> True, load forged file : 4K render OK
    [PATCH] multi_node_sync (Pro feature)              : frame-lock sync enabled
    [PATCH] private_toe (Pro feature)                  : saved private project toy.toe
    [LOADER] cached tier flip on legit load            : 4K render OK
    MEAS v1 patch_verify sites=1 loc=2
    结论: 凭证伪造被签名阻断；但本地检查是"可以被删除的问题"，
    缓存 tier 是"可以被翻转的答案"。攻击者从未需要厂商私钥。

## V2 — 机器绑定

    license bound to system code: a5e1ef370eed94ae
    [LEGIT B] machine B tries machine A's license -> REJECTED (created with different system code)
    [ATTACK] spoof get_system_code -> a5e1ef37... : shared_memory OK
    MEAS v2 spoof_binding sites=1 loc=3
    结论: 绑定确实阻止了朴素复制；但锚点是客户端自报的，
    期望值就明文躺在 license 文件里 — 伪造自报 = 1 个 patch。

## V3 — 分散 enforcement

    gate holds at free tier (private_toe denied)
    HUNT (AST): 4 gate call sites
      network.py:6  call require_tier()
      network.py:11 call require_pro()
      projects.py:11 call gate()
      registry.py:20 call require_tier()
    HUNT (strings): 3 denial-string sites (字符串 xref 发现键)
    PATCH: 3 sites patched (features.projects.gate,
           License.require_tier/require_pro, features.render._gate_render_4k)
    4/4 Pro/Commercial 特性在 free license 下全部解锁
    MEAS v3 hunt_gates sites=4 strings=3 patches=3 loc=5
    结论: 成本随表面积增长（每多一个独立 gate 绑定 = 多一次 patch），
    但结构不变 — 本地 enforcement 仍是最终裁决者。

## 汇总

| V | 防御 | 攻击 | LOC | 位点 | 攻击结果 |
|---|---|---|---|---|---|
| V0 | 无 | 文件/内存翻转 | 1 | 1 | 全开 |
| V1 | 签名 | patch 验证/缓存翻转 | 2 | 1 | 全开 |
| V2 | +绑定 | 伪造自报锚点 | 3 | 1 | 全开 |
| V3 | 分散 gate | 猎杀+逐个 patch | 5 | 4 | 全开 |

## 假说对照

- H1 (same-artifact exposure): V1-V3 全部命中 — 能力实现与裁决逻辑都在
  敌手进程内，防御只涨价不改变可攻击性。
- H2 (local authority collapse): V1 [PATCH] 与 V3 [PATCH] 直接命中 —
  "本地程序检查本地程序"的裁决可以被本地补丁删除。
- H3 (externalized authority): 未测（V6/V7/V8 路线）；V2 的反例显示
  把锚点移到"客户端报告的值"不构成外部化。
- H4 (remote ≠ solved): 未测（V6 路线）— 若服务器只回答 "yes, user is Pro"
  而能力仍在本地，V1/V3 的攻击原样成立。
- H5 (attack economics): V3 给出第一个可度量数据点 — 分散 gate 把成本
  从 O(1) 抬到 O(位数点)，但每个位点仍是 O(1)。


## V4-V8 authority-topology measurements

Clean advanced baseline: **10/10 PASS**.

| V | Observation | Boundary interpretation |
|---|---|---|
| V4 | integrity detector rejects changed bytes; one local enforcement patch then permits local premium module | detection improved, trust domain unchanged |
| V5 | free verifier patch cannot recover absent key; authorized Pro key is extractable and reusable | asset placement changes graph, authorized-recipient leakage remains |
| V6 | signed nonce-bound remote DENY remains authentic; one local enforcement patch permits shipped premium implementation | remote entitlement alone does not externalize capability |
| V7 | local forged primitive receipt fails signature; entitled external primitive verifies | external required primitive changes result-authority boundary; hardware isolation not physically proven |
| V8 | local fake remote output fails signature; entitled service returns verified result; premium implementation is not shipped | capability boundary genuinely externalized |

### Updated hypotheses

- H1: supported with qualification — V5 can withhold plaintext until key delivery; V8 does not ship the protected implementation.
- H2: supported — V4 and V6 add two independent local-authority-collapse treatments.
- H3: semantically supported by V7/V8; physical hardware/cloud hostile-host resistance remains untested.
- H4: directly supported by V6 versus V8.
- H5: supported as a multidimensional economic model, not a single hardness scalar.
