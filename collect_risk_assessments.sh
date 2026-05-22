#!/usr/bin/env bash
# 将指定项目下所有 risk_assessment.json 按 <project>-<tag>-<cve>.json 重命名后打包
#
# 用法:
#   ./collect_risk_assessments.sh [选项]
#
# 选项:
#   -p, --project   项目名称，默认 storm
#   -b, --base-dir  workflow_output 根目录，默认 ./workflow_output
#   -o, --output    输出压缩包路径（不含扩展名），默认 ./<project>_risk_assessments
#   -h, --help      显示帮助

set -euo pipefail

PROJECT="storm"
BASE_DIR="./workflow_output"
OUTPUT=""

usage() {
    sed -n '/^# 用法/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--project)   PROJECT="$2";  shift 2 ;;
        -b|--base-dir)  BASE_DIR="$2"; shift 2 ;;
        -o|--output)    OUTPUT="$2";   shift 2 ;;
        -h|--help)      usage ;;
        *) echo "未知参数: $1" >&2; exit 1 ;;
    esac
done

# 默认输出路径
OUTPUT="${OUTPUT:-${PROJECT}_risk_assessments}"
EVAL_DIR="${BASE_DIR}/eval_runs/${PROJECT}"
STAGE_DIR="${OUTPUT}"

# 检查输入目录
if [[ ! -d "$EVAL_DIR" ]]; then
    echo "错误: 目录不存在: $EVAL_DIR" >&2
    exit 1
fi

# 查找所有 risk_assessment.json
mapfile -t FILES < <(find "$EVAL_DIR" -name "risk_assessment.json")

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "错误: 在 $EVAL_DIR 下未找到任何 risk_assessment.json" >&2
    exit 1
fi

echo "找到 ${#FILES[@]} 个 risk_assessment.json，目标目录: ${STAGE_DIR}/"

# 清空并重建暂存目录
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# 复制并重命名
COPIED=0
for f in "${FILES[@]}"; do
    # 路径结构: .../eval_runs/<project>/<tag>/<cve>/risk_assessment.json
    tag=$(basename "$(dirname "$(dirname "$f")")")
    cve=$(basename "$(dirname "$f")")
    dest="${STAGE_DIR}/${PROJECT}-${tag}-${cve}.json"
    cp "$f" "$dest"
    (( COPIED++ ))
done

echo "复制完成，共 ${COPIED} 个文件"

# 压缩
ARCHIVE="${OUTPUT}.tar.gz"
tar -czf "$ARCHIVE" "$STAGE_DIR"
echo "压缩完成: ${ARCHIVE}（$(du -sh "$ARCHIVE" | cut -f1)）"
