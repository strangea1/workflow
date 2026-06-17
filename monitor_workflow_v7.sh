#!/bin/bash

# 监控workflow运行状态
LOG_FILE="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_run_v7_nvd_fix.log"
EVAL_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/eval_runs"
NVD_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/nvd"

echo "=== Workflow监控 ==="
echo "日志文件: $LOG_FILE"
echo ""

# 检查进程是否在运行
PID=$(ps aux | grep "workflow_unified.py" | grep -v grep | awk '{print $2}')
if [ -z "$PID" ]; then
    echo "❌ workflow进程未运行"
else
    echo "✅ workflow进程运行中 (PID: $PID)"
fi

echo ""
echo "=== 最新日志 ==="
tail -20 "$LOG_FILE"

echo ""
echo "=== NVD抓取进度 ==="
if [ -d "$NVD_DIR" ]; then
    nvd_count=$(find "$NVD_DIR" -name "*_nvd.json" 2>/dev/null | wc -l)
    echo "NVD JSON文件数量: $nvd_count"
else
    echo "NVD目录不存在"
fi

echo ""
echo "=== eval进度 ==="
if [ -d "$EVAL_DIR" ]; then
    for project in storm struts zookeeper shiro; do
        if [ -d "$EVAL_DIR/$project" ]; then
            final_count=$(find "$EVAL_DIR/$project" -name "final_record.json" 2>/dev/null | wc -l)
            echo "$project: $final_count 个final_record.json"
        else
            echo "$project: 未开始"
        fi
    done
else
    echo "eval_runs目录未创建"
fi

echo ""
echo "=== final_assessment.xlsx ==="
if [ -f "/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/final_assessment.xlsx" ]; then
    python3 -c "
import pandas as pd
df = pd.read_excel('/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/final_assessment.xlsx')
print(f'行数: {len(df)}')
print('项目分布:')
print(df['Project'].value_counts())
"
else
    echo "final_assessment.xlsx未生成"
fi
