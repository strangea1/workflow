#!/bin/bash

# 监控hadoop workflow运行状态
LOG_FILE="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_run_hadoop.log"
EVAL_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/eval_runs/hadoop"
NVD_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/nvd"
CODEWIKI_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/target_repo/hadoop"
VFIND_DIR="/home/hqs/eva_pro_lqs/lqs/workflow/workflow_output/vfind/hadoop"
RESULT_FILE="/home/hqs/eva_pro_lqs/lqs/workflow/result_hadoop.xlsx"

echo "=== Hadoop Workflow监控 ==="
echo "日志文件: $LOG_FILE"
echo ""

# 检查进程是否在运行
PID=$(ps aux | grep "workflow_unified.py" | grep "hadoop" | grep -v grep | awk '{print $2}')
if [ -z "$PID" ]; then
    echo "❌ workflow进程未运行"
    # 检查是否已完成
    if [ -f "$RESULT_FILE" ]; then
        echo "✅ 结果文件已生成: $RESULT_FILE"
    fi
else
    echo "✅ workflow进程运行中 (PID: $PID)"
    echo "   运行时间: $(ps -p $PID -o etime= 2>/dev/null)"
fi

echo ""
echo "=== 最新日志 ==="
tail -30 "$LOG_FILE"

echo ""
echo "=== 处理进度 ==="
# 统计已处理的tag数量
if [ -f "$LOG_FILE" ]; then
    processed_tags=$(grep -c "项目 hadoop tag.*提取到" "$LOG_FILE" 2>/dev/null || echo "0")
    echo "已处理tag数量: $processed_tags / 10"
fi

echo ""
echo "=== CodeWiki状态 ==="
if [ -d "$CODEWIKI_DIR" ]; then
    docs_count=$(find "$CODEWIKI_DIR/docs" -name "*.md" 2>/dev/null | wc -l)
    echo "CodeWiki文档数量: $docs_count"
    if [ -f "$CODEWIKI_DIR/docs/overview.md" ]; then
        echo "✅ overview.md 已生成"
    else
        echo "⏳ overview.md 生成中..."
    fi
else
    echo "CodeWiki目录不存在"
fi

echo ""
echo "=== vfind状态 ==="
if [ -d "$VFIND_DIR" ]; then
    vfind_count=$(find "$VFIND_DIR" -name "*.json" 2>/dev/null | wc -l)
    echo "vfind结果数量: $vfind_count"
else
    echo "vfind目录不存在"
fi

echo ""
echo "=== NVD状态 ==="
if [ -d "$NVD_DIR" ]; then
    nvd_count=$(find "$NVD_DIR" -name "hadoop_*_nvd.json" 2>/dev/null | wc -l)
    echo "hadoop NVD文件数量: $nvd_count"
else
    echo "NVD目录不存在"
fi

echo ""
echo "=== eval状态 ==="
if [ -d "$EVAL_DIR" ]; then
    final_count=$(find "$EVAL_DIR" -name "final_record.json" 2>/dev/null | wc -l)
    echo "final_record.json数量: $final_count"
else
    echo "eval目录不存在"
fi

echo ""
echo "=== 结果文件 ==="
if [ -f "$RESULT_FILE" ]; then
    python3 -c "
import pandas as pd
df = pd.read_excel('$RESULT_FILE')
print(f'结果文件行数: {len(df)}')
print('项目分布:')
print(df['Project'].value_counts())
" 2>/dev/null
else
    echo "结果文件未生成"
fi

echo ""
echo "=== 系统资源 ==="
echo "CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
echo "内存使用: $(free -h | awk '/^Mem:/{print $3 "/" $2}')"
echo "磁盘使用: $(df -h / | awk 'NR==2{print $5}')"
echo "负载: $(uptime | awk -F'load average:' '{print $2}')"
