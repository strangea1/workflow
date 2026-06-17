# RADP (Risk Assessment Dataset Package)

## 术语定义

**RADP** (Risk Assessment Dataset Package) 是指将EVA-Pro漏洞风险评估流水线生成的eval结果（`final_record.json`）打包为标准化机器学习数据集的过程。

## 核心特征

1. **标准化命名**: `<项目名称>-<tag名称>-<cve编号>.json`
2. **完整数据**: 包含任务信息、风险评估、漏洞详情
3. **可复现性**: 记录workflow版本和打包参数
4. **即用性**: 可直接用于模型训练和评估

## 使用场景

- **模型训练**: 将打包后的数据集用于训练漏洞风险评估模型
- **模型评估**: 使用标准化数据集评估模型性能
- **数据分析**: 对历史评估结果进行统计分析
- **结果交付**: 将评估结果以标准化格式交付给其他团队

## 快速使用

### 命令行调用

```bash
# 使用默认配置打包所有项目
bash scripts/package_risk_dataset.sh

# 打包指定项目
bash scripts/package_risk_dataset.sh -p "shiro storm"

# 指定目标目录
bash scripts/package_risk_dataset.sh -t /path/to/my/dataset

# 覆盖已有目录
bash scripts/package_risk_dataset.sh -o
```

### 快捷命令

```bash
# 使用RADP快捷命令
scripts/radp                    # 使用默认配置
scripts/radp -p shiro           # 只打包shiro
scripts/radp -o                 # 覆盖已有目录
scripts/radp --help             # 查看帮助
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-e, --eval-dir` | eval_runs目录路径 | `workflow_output/eval_runs` |
| `-t, --target-dir` | 目标输出目录 | `/home/hqs/eva_pro/model/dataset` |
| `-p, --projects` | 项目列表，空格分隔 | `storm struts zookeeper shiro` |
| `-o, --overwrite` | 覆盖已存在的目标目录 | `false` |

## 数据结构

### 文件命名规则

每个JSON文件命名为: `<项目名称>-<tag名称>-<cve编号>.json`

示例:
- `shiro-shiro-root-2.2.0-CVE-2023-41080.json`
- `storm-v1.2.1-CVE-2022-33915.json`

### JSON数据结构

```json
{
  "task": {
    "project": "项目名称",
    "tag": "版本标签",
    "cve": "CVE编号",
    "component": "组件名称",
    "version": "组件版本"
  },
  "risk_assessment": {
    "final_result": {
      "risk_level": "高危|非高危|未取得共识"
    },
    "scoring_factors": {
      "f_vuln": {
        "score": 2.5,
        "sub_factors": {
          "vuln_type": {"label": "...", "score": 0.5},
          "reachability": {"label": "...", "score": 1.0},
          "required_privilege": {"label": "...", "score": 0.5},
          "exploit_complexity": {"label": "...", "score": 0.5}
        }
      },
      "f_threat": {
        "score": 0.9,
        "sub_factors": {
          "exploit_status": {"label": "...", "score": 0.2},
          "intel_confidence": {"label": "...", "score": 0.4},
          "patch_status": {"label": "...", "score": 0.3},
          "related_threat_activity": {"label": "...", "score": 0.0}
        }
      },
      "f_business": {
        "score": 1.5,
        "sub_factors": {
          "system_criticality": {"label": "...", "score": 0.5},
          "business_impact": {"label": "...", "score": 0.5},
          "impact_scope": {"label": "...", "score": 0.5}
        }
      }
    },
    "vulnerability": {
      "vul_cvss_score": "CVSS分数",
      "vul_type": "漏洞类型",
      "vul_cve_age_days": "CVE年龄（天）",
      "vul_kev_in_catalog": "是否在CISA KEV中"
    }
  }
}
```

## Python使用示例

### 加载数据集

```python
import json
from pathlib import Path

def load_radp_dataset(dataset_dir):
    """加载RADP数据集"""
    dataset = {}
    dataset_path = Path(dataset_dir)

    for project_dir in dataset_path.iterdir():
        if not project_dir.is_dir() or project_dir.name.startswith('.'):
            continue

        project_name = project_dir.name
        dataset[project_name] = []

        for json_file in project_dir.glob("*.json"):
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dataset[project_name].append(data)

    return dataset

# 使用示例
dataset = load_radp_dataset("/home/hqs/eva_pro/model/dataset")
for project, records in dataset.items():
    print(f"{project}: {len(records)} 条记录")
```

### 筛选高危CVE

```python
def filter_high_risk(dataset):
    """筛选高危CVE"""
    high_risk = []
    for project, records in dataset.items():
        for record in records:
            risk_level = record.get("risk_assessment", {}).get("final_result", {}).get("risk_level")
            if risk_level == "高危":
                high_risk.append(record)
    return high_risk
```

### 提取特征向量

```python
def extract_features(record):
    """提取特征向量用于模型训练"""
    risk = record.get("risk_assessment", {})
    scoring = risk.get("scoring_factors", {})

    features = {
        # FVuln子因子
        "vuln_type_score": scoring.get("f_vuln", {}).get("sub_factors", {}).get("vuln_type", {}).get("score", 0),
        "reachability_score": scoring.get("f_vuln", {}).get("sub_factors", {}).get("reachability", {}).get("score", 0),
        "privilege_score": scoring.get("f_vuln", {}).get("sub_factors", {}).get("required_privilege", {}).get("score", 0),
        "complexity_score": scoring.get("f_vuln", {}).get("sub_factors", {}).get("exploit_complexity", {}).get("score", 0),

        # FThreat子因子
        "exploit_status_score": scoring.get("f_threat", {}).get("sub_factors", {}).get("exploit_status", {}).get("score", 0),
        "intel_confidence_score": scoring.get("f_threat", {}).get("sub_factors", {}).get("intel_confidence", {}).get("score", 0),
        "patch_status_score": scoring.get("f_threat", {}).get("sub_factors", {}).get("patch_status", {}).get("score", 0),

        # FBusiness子因子
        "system_criticality_score": scoring.get("f_business", {}).get("sub_factors", {}).get("system_criticality", {}).get("score", 0),
        "business_impact_score": scoring.get("f_business", {}).get("sub_factors", {}).get("business_impact", {}).get("score", 0),
        "impact_scope_score": scoring.get("f_business", {}).get("sub_factors", {}).get("impact_scope", {}).get("score", 0),

        # CVSS分数
        "cvss_score": float(risk.get("vulnerability", {}).get("vul_cvss_score", 0) or 0),

        # 标签
        "risk_level": risk.get("final_result", {}).get("risk_level", "unknown")
    }

    return features
```

## 目录结构

```
<target_dir>/
├── README_RADP.md                    # 自动生成的说明文档
├── storm/
│   ├── storm-v1.2.1-CVE-xxxx.json
│   └── ...
├── struts/
│   ├── struts-struts2-parent-2.3.14.1-CVE-xxxx.json
│   └── ...
├── zookeeper/
│   ├── zookeeper-release-3.7.0-CVE-xxxx.json
│   └── ...
└── shiro/
    ├── shiro-shiro-root-2.2.0-CVE-xxxx.json
    └── ...
```

## 相关脚本

- **打包脚本**: `scripts/package_risk_dataset.sh`
- **监控脚本**: `monitor_workflow.sh`
- **分析脚本**: `docs/shiro_v5_analysis.md`, `docs/shiro_v6_analysis.md`

## 版本历史

- **v1.0** (2026-06-01): 初始版本，支持storm/struts/zookeeper/shiro四个项目
- 支持v7修复后的完整sub_factors输出
- 自动生成README_RADP.md说明文档

## 术语使用约定

在项目文档和代码中，使用以下约定：

1. **完整术语**: "RADP (Risk Assessment Dataset Package)" - 用于正式文档
2. **简称**: "RADP" - 用于代码注释和日常交流
3. **动词形式**: "执行RADP打包" 或 "RADP打包" - 用于描述操作

示例：
- "请执行RADP打包，将shiro和storm的数据集打包到指定目录"
- "使用RADP脚本打包eval结果"
- "RADP数据集已准备好，可以用于模型训练"
