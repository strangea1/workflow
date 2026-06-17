#!/bin/bash
# ============================================================================
# Risk Assessment Dataset Packager (RADP)
# 将eval_runs目录中的final_record.json打包为标准化数据集
# ============================================================================

set -e

# 默认配置
DEFAULT_EVAL_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/eval_runs"
DEFAULT_TARGET_DIR="/home/hqs/eva_pro/model/dataset"
DEFAULT_PROJECTS="storm struts zookeeper shiro"

# 显示帮助信息
show_help() {
    cat << EOF
Risk Assessment Dataset Packager (RADP)
用法: $0 [选项]

选项:
    -e, --eval-dir DIR      eval_runs目录路径 (默认: $DEFAULT_EVAL_DIR)
    -t, --target-dir DIR    目标输出目录 (默认: $DEFAULT_TARGET_DIR)
    -p, --projects LIST     项目列表，空格分隔 (默认: $DEFAULT_PROJECTS)
    -o, --overwrite         覆盖已存在的目标目录
    -h, --help              显示此帮助信息

术语说明:
    此脚本执行的打包方式称为 "RADP" (Risk Assessment Dataset Package)
    即：将EVA-Pro流水线生成的eval结果打包为标准化的机器学习数据集

示例:
    # 使用默认配置打包所有项目
    $0

    # 打包指定项目
    $0 -p "shiro storm"

    # 指定目标目录
    $0 -t /path/to/my/dataset

    # 覆盖已有目录
    $0 -o

EOF
}

# 解析命令行参数
EVAL_DIR="$DEFAULT_EVAL_DIR"
TARGET_DIR="$DEFAULT_TARGET_DIR"
PROJECTS="$DEFAULT_PROJECTS"
OVERWRITE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--eval-dir)
            EVAL_DIR="$2"
            shift 2
            ;;
        -t|--target-dir)
            TARGET_DIR="$2"
            shift 2
            ;;
        -p|--projects)
            PROJECTS="$2"
            shift 2
            ;;
        -o|--overwrite)
            OVERWRITE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
done

# 验证源目录
if [ ! -d "$EVAL_DIR" ]; then
    echo "错误: eval_runs目录不存在: $EVAL_DIR"
    exit 1
fi

# 创建目标目录
mkdir -p "$TARGET_DIR"

# 打包统计
total_files=0
declare -A project_counts

echo "============================================================================"
echo "Risk Assessment Dataset Packager (RADP)"
echo "============================================================================"
echo "源目录: $EVAL_DIR"
echo "目标目录: $TARGET_DIR"
echo "项目列表: $PROJECTS"
echo "============================================================================"
echo ""

# 处理每个项目
for project in $PROJECTS; do
    echo "=== 处理 $project ==="

    # 创建项目目录
    project_target="$TARGET_DIR/$project"
    if [ -d "$project_target" ] && [ "$OVERWRITE" = true ]; then
        rm -rf "$project_target"
        echo "已删除旧目录: $project_target"
    fi
    mkdir -p "$project_target"

    # 检查源目录
    project_source="$EVAL_DIR/$project"
    if [ ! -d "$project_source" ]; then
        echo "警告: 源目录不存在，跳过: $project_source"
        continue
    fi

    # 查找并复制文件
    count=0
    while IFS= read -r -d '' file; do
        # 从路径中提取tag和cve
        # 路径格式: eval_runs/<项目>/<tag>/<CVE>/final_record.json
        rel_path="${file#$project_source/}"
        tag=$(echo "$rel_path" | cut -d'/' -f1)
        cve=$(echo "$rel_path" | cut -d'/' -f2)

        # 新文件名: 项目名称-tag名称-cve编号.json
        new_filename="${project}-${tag}-${cve}.json"

        # 复制文件
        cp "$file" "$project_target/$new_filename"
        count=$((count + 1))
    done < <(find "$project_source" -name "final_record.json" -print0)

    project_counts[$project]=$count
    total_files=$((total_files + count))
    echo "已复制 $count 个文件到 $project_target"
    echo ""
done

# 显示统计信息
echo "============================================================================"
echo "打包完成"
echo "============================================================================"
echo "目标目录: $TARGET_DIR"
echo ""
echo "项目统计:"
for project in $PROJECTS; do
    count=${project_counts[$project]:-0}
    echo "  $project: $count 个文件"
done
echo ""
echo "总计: $total_files 个文件"
echo ""

# 创建README文件
readme_file="$TARGET_DIR/README_RADP.md"
cat > "$readme_file" << EOF
# Risk Assessment Dataset Package (RADP)

## 打包信息

- **打包时间**: $(date)
- **数据来源**: $EVAL_DIR
- **打包工具**: scripts/package_risk_dataset.sh

## 数据集统计

| 项目 | 文件数量 |
|------|---------|
EOF

for project in $PROJECTS; do
    count=${project_counts[$project]:-0}
    echo "| $project | $count |" >> "$readme_file"
done

cat >> "$readme_file" << EOF
| **总计** | **$total_files** |

## 文件命名规则

每个JSON文件命名为: \`<项目名称>-<tag名称>-<cve编号>.json\`

示例:
- \`shiro-shiro-root-2.2.0-CVE-2023-41080.json\`
- \`storm-v1.2.1-CVE-2022-33915.json\`

## 数据结构

每个JSON文件包含以下字段:

\`\`\`json
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
      "f_vuln": { "score": 2.5, "sub_factors": {...} },
      "f_threat": { "score": 0.9, "sub_factors": {...} },
      "f_business": { "score": 1.5, "sub_factors": {...} }
    },
    "vulnerability": {
      "vul_cvss_score": "CVSS分数",
      "vul_type": "漏洞类型"
    }
  }
}
\`\`\`

## 使用说明

### Python加载示例

\`\`\`python
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
\`\`\`

### 筛选高危CVE

\`\`\`python
def filter_high_risk(dataset):
    """筛选高危CVE"""
    high_risk = []
    for project, records in dataset.items():
        for record in records:
            risk_level = record.get("risk_assessment", {}).get("final_result", {}).get("risk_level")
            if risk_level == "高危":
                high_risk.append(record)
    return high_risk
\`\`\`

## 术语说明

**RADP (Risk Assessment Dataset Package)**

指将EVA-Pro漏洞风险评估流水线生成的eval结果（final_record.json）打包为标准化机器学习数据集的过程。

核心特征：
1. **标准化命名**: 项目名称-tag名称-cve编号.json
2. **完整数据**: 包含任务信息、风险评估、漏洞详情
3. **可复现性**: 记录workflow版本和打包参数
4. **即用性**: 可直接用于模型训练和评估

EOF

echo "已创建README文件: $readme_file"
echo ""
echo "============================================================================"
echo "RADP打包完成！"
echo "============================================================================"
