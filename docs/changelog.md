# 代码修改历史

记录对 workflow 代码的已知 bug 修复与改进，按修复轮次组织。

---

## v7（2026-05-27）bug 修复

### workflow_unified.py — 确定性不可达路径 sub_factors 空对象修复

**位置**：`run_eval_pipeline`，`vulnerability_info is None` 分支；`_zero_fbusiness`

**问题**：当 CVE 同时满足"vfind 判定不可达"和"无 NVD 数据"时，走确定性路径直接写入 `risk_assessment.json`，此路径将三个因子的 `sub_factors` 全部写为空对象 `{}`：

```json
"f_vuln":     {"score": 0.0, "details": "缺少 NVD 数据，无法评估", "sub_factors": {}}
"f_threat":   {"score": 0.0, "details": "缺少 NVD 数据，无法评估", "sub_factors": {}}
"f_business": {"score": 0.0, "details": "漏洞不可达，业务影响为零", "sub_factors": {}}
```

此外 `_zero_fbusiness` 仅对已存在的子因子清零，当 `sub_factors` 本身为空时无法补入标准键，导致 LLM 投票路径若出现空 sub_factors 同样无法修复。

**修复（两处）**：

1. **确定性路径**：将 `sub_factors: {}` 替换为带标准键名的骨架，分值全置 0.0：

   - `f_vuln`：`vuln_type / reachability / required_privilege / exploit_complexity`，label 统一为 `"无法评估（缺少NVD数据）"`（reachability label 为 `"不可达"`）
   - `f_threat`：`exploit_status / intel_confidence / patch_status / related_threat_activity`，label 同上
   - `f_business`：`system_criticality / business_impact / impact_scope`，label 为 `"漏洞不可达，业务影响为零"`

2. **`_zero_fbusiness`**：新增模块级常量 `_FBUSINESS_SUB_KEYS`，改用 `setdefault` 确保 `sub_factors` 字典存在后，逐 key 检查：已存在则清零，缺失则补入骨架条目 `{"label": "漏洞不可达，业务影响为零", "score": 0.0}`。

**效果**：所有路径下的 `risk_assessment.json` 三因子均输出完整的标准子因子列表，不再出现 `sub_factors: {}` 的空对象。

---

## v3（2026-05-14）合并修复

结合两位开发者的修改方案，在 v2 基础上新增以下修复：

### workflow_unified.py — CVSS Primary 优先提取

**位置**：`load_nvd_vulnerability_info`，CVSS 提取循环

**问题**：NVD 的 `cvssMetricV31` 列表中可能同时存在 `type=Primary`（NVD 官方）和 `type=Secondary`（第三方扫描器）两条记录，原代码直接取 `values[0]`，当 Secondary 排在首位时会取到非官方评分。

**修复**：优先选 `type == "Primary"` 或 `source == "nvd@nist.gov"` 的条目，找不到时回退到 `values[0]`。

```python
primary = next(
    (m for m in values if m.get("type") == "Primary" or m.get("source") == "nvd@nist.gov"),
    None,
)
metric = primary if primary else values[0]
```

---

### workflow_unified.py — CWE 多值合并

**位置**：`load_nvd_vulnerability_info`，weaknesses 提取

**问题**：原代码只取 `weaknesses[0].description[0]`，当一个 CVE 关联多个 CWE 时（如 `CWE-284, NVD-CWE-Other`）会丢失后续条目。

**修复**：遍历所有 `weaknesses[].description[]`，去重后以逗号合并。

```python
seen_cwes: list = []
for w in weaknesses:
    if isinstance(w, dict):
        for d in (w.get("description") or []):
            val = str(d.get("value") or "") if isinstance(d, dict) else str(d)
            if val and val not in seen_cwes:
                seen_cwes.append(val)
vul_type = ", ".join(seen_cwes)
```

---

### run_codewiki_pipline.py — CodeWiki `<OVERVIEW>` 防崩溃补丁

**位置**：新增 `patch_codewiki_overview_retry()`，在 `prepare_and_run_codewiki()` 中调用

**问题**：CodeWiki 内部在生成父模块文档时执行 `parent_docs.split("<OVERVIEW>")[1]`，当模型输出不包含 `<OVERVIEW>` 标签时触发 `IndexError`，导致整个 CodeWiki 生成失败。

**修复**：monkey patch `codewiki.src.be.documentation_generator.call_llm`：
1. 若模型输出缺少 `<OVERVIEW>`，先附加更严格提示重试一次
2. 重试仍缺失则自动包裹：`<OVERVIEW>\n{response}\n</OVERVIEW>`

---

## v2（2026-05-13）修复

### workflow_unified.py — patch_status 启发式补全

**问题**：NVD references 极少使用 `"Patch"` tag，通常用 `"Vendor Advisory"` 标注厂商公告，原代码仅检测 `"Patch"` tag 导致所有历史 CVE 的 `vul_patch_available = False`，FThreat 系统性虚高约 +0.6。

另有次级 bug：时间兜底逻辑使用 `datetime.now(timezone.utc)` 与 NVD 的朴素日期字符串相减，触发 `TypeError` 被 `except Exception: pass` 静默吞掉，时间兜底从未生效。

**修复**：三层递进判断：
1. NVD references 含 `"Patch"` tag
2. NVD references 含 `"Vendor Advisory"` tag
3. `vulnStatus ∈ {Analyzed, Modified}` 且发布超过 365 天（统一朴素日期比较）

---

### workflow_unified.py — eval 任务去重

**问题**：同一项目下多个子模块依赖相同组件的不同版本（如 Tomcat 10.1.49 和 9.0.112），`build_analysis_tasks` 会为同一 `(project, tag, cve)` 组合生成多个任务，导致重复 LLM 调用，且两次结果不一致时被标为"未取得共识"。

**修复**：`build_analysis_tasks` 中加入 `seen: Set[tuple]`，按 `(project, tag, cve)` 去重，只保留首次命中的版本记录。

---

### eval/src/risk_asssignment.py — prepare_assessment_input 防御性访问

**问题**：`prepare_assessment_input` 直接用 `business_factors["project"]` 访问，当 `component_summary` 结构不完整（缺少顶层 `"project"` 键）时抛出 `KeyError: 'project'`，投票结果记录为 `{"error": "'project'"}`，风险等级为 `None`。

**修复**：全部改用 `.get()` + 空值兜底：
```python
project = business_factors.get("project") or {}
component = business_factors.get("component") or {}
impact = component.get("impact_analysis") or {}
```

---

## v1（2026-05-12）修复

### workflow_unified.py — NVD JSON 解析层级

**问题**：NVD API v2 返回结构为 `payload["vulnerabilities"][0]["cve"]`，原代码直接访问 `payload["cve"]` 导致 `KeyError`。

**修复**：优先读取 `payload["vulnerabilities"][0]["cve"]`，兼容旧结构 `payload["cve"]`。

---

### workflow_unified.py — call_openai_judge prompt 格式化崩溃

**问题**：prompt 字符串中含有 `{"affected": ...}` 的 JSON 示例，对其调用 `.format(component=component)` 时 Python 的 `str.format()` 将 `{affected}` 等字段当作格式占位符，触发 `KeyError: '"affected"'`。

**修复**：移除 `.format()` 调用，改为 f-string 拼接。

---

### workflow_unified.py — vul_patch_available / vul_poc_available 硬编码

**问题**：原代码将这两个字段硬编码为 `False`，完全忽略 NVD references 中的标签信息。

**修复**：基于 `references[].tags` 动态判断（`"Exploit"` / `"Proof of Concept"` 等标签）。

---

### workflow_unified.py — description_mentions_component 过度放行

**问题**：`return True` 无条件放行，导致 XWiki、Python、libpcre 等与目标组件无关的 CVE 全部通过匹配，产生大量误报。

**修复**：按别名关键词过滤，对 Groovy/log4j 加入首句主体过滤；`call_openai_judge` prompt 加入 `is_direct` 判断，要求 LLM 区分 CVE 主体与技术依赖方。

---

## v4（2026-05-21）新增功能

### workflow_unified.py — CVSS 分数写入输出列

**位置**：`run_eval_pipeline`，`load_nvd_vulnerability_info` 调用时机调整

**问题**：NVD 拉取的 CVSS 分数已经存在于 `vulnerability_info["vul_cvss_score"]`，但从未写入最终的 `final_assessment.xlsx`，开发者无法在汇总表中直接看到 CVSS 与风险等级的对应关系。

另：原代码在 `module_locator` / `component_summarizer` 两个 LLM 步骤之后才调用 `load_nvd_vulnerability_info`，导致不可达 CVE 在被跳过前无法拿到 CVSS。

**修复**：
1. `row` 初始化时加入 `"CVSS": ""` 列
2. 将 `load_nvd_vulnerability_info` 前移至 vfind 解析之后、可达性判断之前
3. 紧接着写 `row["CVSS"] = vulnerability_info.get("vul_cvss_score", "") if vulnerability_info else ""`

---

### workflow_unified.py — 不可达 CVE 保留并将业务因子置零

**位置**：`build_analysis_tasks`、`run_eval_pipeline`，新增 `_zero_fbusiness`

**问题**：vfind 判定触发点不可达的 CVE 被直接丢弃（`Status = "skipped"`），导致数据集中低危漏洞严重不足，风险等级分布失真（高危占比 ~88%）。

**修复（三处联动）**：

1. **`build_analysis_tasks`**：原来仅允许 `non_empty_sinks.json` 中的可达 CVE 进入任务列表。新增逻辑：不在触发集合内但存在 vfind JSON 文件的 CVE（即不可达 CVE）同样纳入任务。

   ```python
   vfind_json = find_vfind_result(project, cve)
   in_triggered = bool(triggered_set and cve in triggered_set)
   if not in_triggered and not vfind_json:
       continue
   ```

2. **`_zero_fbusiness`**：新增辅助函数，将 `f_business` 总分与所有子因子强制置 0，details 更新为"漏洞不可达，业务影响为零"。

3. **`run_eval_pipeline` 不可达分支**：
   - 提前写 `trigger_analysis.json`
   - **若有 NVD 数据**：构造最小业务上下文（非空 dict，防止 `run_risk_assessment` 回落读本地文件），以 `reachability="不可达"` 调用 LLM vote，每次 vote 结果出来后调用 `_zero_fbusiness` 强制置零，聚合后再次调用 `_zero_fbusiness`
   - **若无 NVD 数据**：跳过 LLM，直接写确定性低危记录（三因子全 0，`risk_level="低危"`），避免回落读取本地 `eval/cve_data/` 文件触发 `FileNotFoundError`
   - `Status = "success"`，`FBusiness = 0.0`，写入 `final_record.json`

**效果（shiro v5 验证）**：

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 有风险等级条数 | 17 | 43 |
| 低危 | 0（0%） | 27（63%） |
| 高危 | ~15（88%） | 11（26%） |
| 不可达 CVE 空 RiskLevel | — | 0 |

---

## v6（2026-05-22）新增功能

### workflow_unified.py — CISA KEV 威胁情报接入

**位置**：新增 `_load_kev_catalog()`，在 `load_nvd_vulnerability_info` 中调用；`eval/src/risk_asssignment.py` 的 `prepare_assessment_input` 新增 `threat_intel_context` 字段

**问题**：FThreat 多数 CVE 固定为 1.80，LLM 无差别给出均值应答，方差≈0，"已在野利用"与"仅有学术 PoC"无法区分。

**修复**：
1. `_load_kev_catalog()`：首次调用时下载 CISA KEV JSON，解析为 CVE ID 集合，写入 `workflow_output/kev_catalog.json` 本地缓存，后续直接读取不再下载。
2. `load_nvd_vulnerability_info` 返回值新增两个字段：
   - `vul_kev_in_catalog: bool`（该 CVE 是否收录于 CISA KEV）
   - `vul_cve_age_days: int`（CVE 发布至今的天数，由 NVD `published` 字段计算）
3. `prepare_assessment_input` 将上述字段拼合为 `threat_intel_context` 字符串，作为新增 prompt 变量传入 LLM，明确告知 KEV 状态、CVE 年龄、PoC/补丁状态。
4. `RISK_ASSESSMENT_HUMAN_PROMPT` 新增 `{threat_intel_context}` 行。

**效果（shiro v6 验证）**：FThreat 方差从≈0 升至 0.360，取值从 3 种增至 13 种，KEV 命中 CVE 的 FThreat 显著升分（CVE-2016-4437: 1.80→2.5，CVE-2025-24813: skipped→3.15）。

---

### workflow_unified.py — FVuln CVSS 分段后置上限（`_cap_fvuln_by_cvss`）

**位置**：新增 `_cap_fvuln_by_cvss(payload, cvss_str)`，在 `run_eval_pipeline` 的 `aggregate_votes` 之后调用

**问题**：可达 CVE 的 FVuln 均值 3.62/4.0，LLM 无论 CVSS 高低几乎都将四个子因子打满，导致 CVSS 5.x 漏洞与 CVSS 9.8 漏洞得分相近。

**修复**：按 CVSS 分段施加等比压缩上限，保持子因子内部相对权重不变：

```
CVSS < 4.0   → FVuln ≤ 1.5
CVSS 4.0–6.9 → FVuln ≤ 2.5
CVSS 7.0–8.9 → FVuln ≤ 3.5
CVSS ≥ 9.0   → 不限制
```

超出上限时，`f_vuln.score` 设为上限值，所有子因子 score 按相同比例等比缩放（`ratio = cap / current_score`）。无 CVSS 数据时跳过约束。

**效果（shiro v6 验证）**：FVuln 均值从 3.62 降至 3.11，CVSS 4.0–6.9 段均值从~3.50 降至 2.46，CVSS 8.8 被精确压缩至上限 3.5。

---

### workflow_unified.py — module locator 两级回退

**位置**：`run_eval_pipeline`，原 `module locator returned empty component` skip 块

**问题**：vfind 触发点落在拦截器、过滤器等横切代码中，module_locator 无法映射，返回空 component，导致 12 条可达 CVE（含 4 条 CVSS 9.8）直接 skipped。

**修复**：将原来的直接 skip 替换为两级回退：

1. **回退一（fallback_component）**：用 `task.component`（Excel 中的依赖名）调用 `run_component_summarizer`，搜索最近似的模块文档。成功时 `Module` 列写入 `"fallback_component"`。
2. **回退二（fallback_overview）**：读取 `target_repo/<项目>/docs/overview.md` 前 3000 字符，构造最小业务上下文 dict，跳过 summarizer 直接进入 vote 循环。成功时 `Module` 列写入 `"fallback_overview"`。
3. 两级均失败时才输出 `Status=skipped`，Error 信息更新为 `"module locator returned empty component, all fallbacks failed"`。

**效果（shiro v6 验证）**：skipped 从 12 条降为 0 条，9 条通过 fallback_overview 补齐评级（回退一在 shiro 上因依赖名与模块文档不匹配而失败，回退二全部成功）。

---

### codewiki/cli/config_manager.py — keyring 无 TTY 阻塞修复

**位置**：`_check_keyring_available()`、`load()`、`get_api_key()`；`run_codewiki_pipline.py` 的 `run_codewiki()`

**问题**：eval 阶段会对每个项目调用 CodeWiki 重新生成文档。CodeWiki 在初始化时通过 `CryptFileKeyring` 读取 API Key，该后端需调用 `getpass.getpass()` 弹出密码提示。在 `nohup` 后台运行时：
- 若终端仍开着（流程运行初期），`getpass` 可访问 `/dev/tty`，成功读取密码并缓存，不报错
- 若终端已关闭（深夜 eval 阶段），`/dev/tty` 不可访问，进程收到 `SIGTTIN` 挂起或读取空密码导致 `InvalidToken` 异常，触发 `sys.exit(1)` 进而 `SystemExit(1)` 在 workflow 中被重新抛出，整个 eval 阶段崩溃

**修复（两处联动）**：

1. **`config_manager.py` — `_check_keyring_available()`**：在函数入口加 `os.isatty(0)` 检测，无 TTY 时直接返回 `False`，跳过所有 keyring 调用：

   ```python
   import os
   if not os.isatty(0):
       return False
   ```

2. **`config_manager.py` — `get_api_key()`**：新增 `credentials.json` fallback，当 keyring 不可用时从 `~/.codewiki/credentials.json` 读取明文 API Key：

   ```python
   if self._api_key is None and CREDENTIALS_FILE.exists():
       try:
           creds = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
           self._api_key = creds.get("api_key")
       except Exception:
           pass
   ```

3. **`run_codewiki_pipline.py` — `run_codewiki()`**：在调用 CodeWiki 前追加环境变量兜底，强制将 keyring 后端替换为空实现，作为双重保险：

   ```python
   os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
   ```

---

### 风险分类改为高危 / 非高危

**位置**：`eval/final_result_system_prompt/prompt2.md`、`prompt1.md`、`eval/src/risk_asssignment.py`、`workflow_unified.py` 确定性不可达路径

**问题**：高危/中危/低危三级分类粒度过细，中危与低危的边界在实际使用中意义不大，且 LLM 区分三级的一致性低。

**修复**：
1. `prompt2.md`：输出要求中 `risk_level` 取值改为 `高危 / 非高危`；同步修复文件内容重复（原 404 行→218 行）。
2. `prompt1.md`：同步调整。
3. `RiskAssessmentResult.risk_level` 字段描述改为 `"风险等级：高危/非高危"`。
4. `workflow_unified.py` 确定性不可达路径的硬编码 `"低危"` 改为 `"非高危"`。

---

### prompt2.md / prompt1.md — 校准规则新增

**位置**：`eval/final_result_system_prompt/prompt2.md` 和 `prompt1.md`

**FVuln 校准规则**：在 FVuln 评分说明后新增强制约束段落，要求 LLM 按 CVSS 分段控制 FVuln 总分上限（与代码层 `_cap_fvuln_by_cvss` 双保险）。

**FThreat 校准规则**：在 FThreat 评分说明后新增参考规则，明确 CISA KEV 收录 → `exploit_status` 必须评为"已在野利用（1.0）"，CVE 发布超过 3 年且有补丁 → `patch_status` 可评最低档，信号缺失时保守评分。

---

## 已知待改进项

| 问题 | 说明 |
|---|---|
| CVSS 5.x 被评高危（FBusiness 主导） | FVuln 已压缩至 2.5，但 FBusiness=2.8（认证框架）驱动最终高危；可选增加后置规则：CVSS < 5.5 且无 KEV → 非高危 |
| 未取得共识无裁决规则 | `--vote 2` 出现分歧时建议自动追加第 3 票以多数决；shiro v6 出现 2 条 |
| 不可达 CVE 无 CVSS | 无 NVD 数据的不可达 CVE 走确定性非高危路径，CVSS 列为空；需在 `--run-nvd` 阶段将不可达 CVE 也纳入拉取范围 |
| FBusiness 区分度不足 | 可达 CVE 的 FBusiness 多数聚集在 2.5–3.0，overview.md 回退路径精度低于 module 级文档；需提升 CodeWiki 模块覆盖率 |
