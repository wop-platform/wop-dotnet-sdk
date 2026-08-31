#!/usr/bin/env bash
# 变异测试入口：行级等价排除经 CLI 传递（Stryker 4.16 config mutate 键忽略 span，
# 仅 CLI -m 生效——三轮对照实验钉死，见 gen-stryker-excludes.py 文档）。
# 用法: scripts/mutation-test.sh [额外 dotnet-stryker 参数...]
set -euo pipefail
cd "$(dirname "$0")/.."

python3 scripts/gen-stryker-excludes.py --check

# 排除参数生成失败必须终止（process substitution 会吞非零退出码：
# 显式落盘临时文件，生成失败时 set -e 生效，杜绝「空排除跑全量」的静默漂移）
SPAN_FILE=$(mktemp)
trap 'rm -f "$SPAN_FILE"' EXIT
python3 scripts/gen-stryker-excludes.py > "$SPAN_FILE"

ARGS=()
while IFS= read -r span; do
  ARGS+=(-m "$span")
done < "$SPAN_FILE"

dotnet tool run dotnet-stryker "${ARGS[@]}" "$@"
