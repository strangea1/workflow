#!/bin/bash
# ============================================================================
# RADP快速调用示例
# 展示如何使用RADP打包脚本
# ============================================================================

echo "=== RADP快速调用示例 ==="
echo ""

# 示例1: 使用默认配置打包所有项目
echo "示例1: 使用默认配置打包所有项目"
echo "命令: bash scripts/package_risk_dataset.sh"
echo ""

# 示例2: 打包指定项目
echo "示例2: 打包指定项目（shiro和storm）"
echo "命令: bash scripts/package_risk_dataset.sh -p \"shiro storm\""
echo ""

# 示例3: 指定目标目录
echo "示例3: 指定目标目录"
echo "命令: bash scripts/package_risk_dataset.sh -t /path/to/my/dataset"
echo ""

# 示例4: 覆盖已有目录
echo "示例4: 覆盖已有目录"
echo "命令: bash scripts/package_risk_dataset.sh -o"
echo ""

# 示例5: 完整参数示例
echo "示例5: 完整参数示例"
echo "命令: bash scripts/package_risk_dataset.sh \\"
echo "  -e /path/to/eval_runs \\"
echo "  -t /path/to/output/dataset \\"
echo "  -p \"shiro storm struts zookeeper\" \\"
echo "  -o"
echo ""

echo "=== 常用场景 ==="
echo ""

echo "场景1: 重新打包所有项目（覆盖旧数据）"
echo "命令: bash scripts/package_risk_dataset.sh -o"
echo ""

echo "场景2: 只打包新运行的项目"
echo "命令: bash scripts/package_risk_dataset.sh -p \"storm struts\""
echo ""

echo "场景3: 打包到指定目录用于模型训练"
echo "命令: bash scripts/package_risk_dataset.sh -t /home/hqs/eva_pro/model/dataset"
echo ""

echo "=== 注意事项 ==="
echo ""
echo "1. 默认源目录: workflow_output/eval_runs"
echo "2. 默认目标目录: /home/hqs/eva_pro/model/dataset"
echo "3. 默认项目: storm struts zookeeper shiro"
echo "4. 使用 -o 参数覆盖已有目录"
echo "5. 打包完成后会自动生成 README_RADP.md"
echo ""

echo "=== 查看详细帮助 ==="
echo "命令: bash scripts/package_risk_dataset.sh --help"
