# WOP 六仓变异测试横评：等价处置模式与 PR 级漂移防线（2026-08-31）

> 背景：wop-dotnet-sdk 变异闭环（Stryker.NET 1194 变异体 → 99.87%，唯一幸存实证
> 为工具覆盖映射伪存活）沉淀出「**用变异排除为显式意图买单**」模式：等价变异
> 逐条论证 → 排除配置入版本控制 → 锚点漂移检测每 PR 显性失败。本次将该模式
> 复用到六仓，并把锚点防线挂到各仓 CI。
> 依据：wop-specs `sdk/wop-sdk-spec.md` D6（幸存体逐个归档举证）与 D7 起草稿
> （击杀率 ≥90% 门禁档位 + 等价清单评审 + 工具口径注记）。

## 1. 六仓现状矩阵（横评终态）

| 仓 | 引擎 | 等价处置 | 分母口径 | PR 级防线 | 锚点漂移检测 |
|---|---|---|---|---|---|
| dotnet | Stryker.NET 4.16 + `scripts/mutation-test.sh` | span 排除（`gen-stryker-excludes.py` 15 组逐条论证） | 剔除（span 经 CLI，config 键无效 → [stryker-net#3814](https://github.com/stryker-mutator/stryker-net/issues/3814)） | ✅ ci.yml `equivalent-anchors` job（本次） | ✅ 17 锚 `--check`（本次挂 CI）|
| java | PIT（CI 定期档）+ 自研 `mutation-check.py`（14 点文本快照，过渡） | 14 点全击杀（无需等价清单） | 全量 | ✅ ci.yml `equivalent-anchors` job（本次） | ✅ 14 快照秒级校验（本次新增 `check-equivalent-anchors.py`）|
| go | 自研 AST 引擎 `tools/mutation` | 口径B：诊断文案族剔除（引擎内） | 剔除文案族 | ✅ 原有 `mutation-diff` 每 PR 增量变异 | 引擎内实现（无行号清单，不适用锚点模式）|
| typescript | 自研 `run-mutations.mjs` | `EQUIVALENT-MUTANTS.md` 15 条逐一举证 | **不剔除**（幸存留分母，94.27%） | ✅ ci.yml `equivalent-anchors` job（本次） | ✅ 15 锚（清单补锚列 + 本次检测脚本）|
| python | 自研 `mutation_test.py`（14 算子） | 白名单 5 条（内嵌论证注释 + 运行时失配告警） | 剔除白名单 | ✅ ci.yml `equivalent-anchors` job（本次） | ✅ 5 锚快照 `tests/equivalent-anchors.txt`（本次）|
| php | `.ci/mutation-run.php` | **原无论证**（46 幸存仅列位置） | 不剔除（90.69%） | ✅ ci.yml `equivalent-anchors` job（本次） | ✅ 40 唯一锚（本次新建清单，41 条 TODO 待 owner 论证）|

## 2. 统一模式（本次落地形态）

```
等价清单（位置/算子/锚/论证）     ← 论证是入册前提（D6）；未论证条目标 TODO 且
                                    不得从分母剔除（php 41 条现状）
  + 排除配置（随仓工具原生机制）    ← dotnet=CLI span / python=白名单 / go=引擎口径B
  + 锚点检测脚本（秒级，--check）   ← 清单行号随源码演进漂移 → PR 显性失败
  + CI PR job                      ← 防线从「跑变异时」提前到「每 PR」
```

## 3. 锚点防线的实证（本次当场发生）

dotnet 仓在变基 origin/main（含 1459 行 docstring 增补）后，等价清单 **15 组
行号中 9 组位移**——若防线缺席，Stryker span 排除将静默指向错误代码（等价主张
失指、击杀率虚化）。`--check` 立即拦截，按锚内容自动重定位（9 MOVE + 1 解析
偏差不影响结果）后恢复全绿。**这正是各仓挂 PR job 的理由。**

## 4. 分母口径分歧（待 D7 评审定夺）

- 剔除派（dotnet/python/go）：等价论证 → 排除 → 分母干净，但排除配置是审查重点
- 保留派（typescript/php）：幸存留分母，分数保守，无需排除配置
- 建议：D7 允许两种口径并存，但**剔除必须举证 + PR 评审**；保留派若幸存含真
  伪存活（如 dotnet m533 教训），需警惕分数低估——TS 15 条已举证、php 46 条
  未论证是当前最大缺口。

## 5. 后续动作

- [ ] php 41 条 TODO 由仓 owner 逐条论证（或补测试击杀——str-empty 文案族建议
      参照 dotnet `ErrorContractTests` 补关键词断言后击杀，而非剔除）
- [ ] D7 起草稿经 wop-specs PR 评审合入（含本横评六仓矩阵为附录素材）
- [ ] stryker-net#3814/#3815 上游跟进（config span 无效 / coveredBy 伪存活）
