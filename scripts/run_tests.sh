#!/usr/bin/env bash
# 工厂测试门（wop-dotnet-sdk 本地化）——dotnet build + dotnet test 全量（388 tests）。
# 用法: scripts/run_tests.sh [--no-lock] [dotnet-args...]
#   --no-lock 为工厂链约定旗标（上游 run_tests.sh 的锁语义），本仓无锁，消费并忽略。
# 证据形态：dotnet test 控制台逐测试输出 + 失败堆栈（退出码 0/1 语义与工厂链一致）。
set -euo pipefail
ARGS=()
for a in "$@"; do
  [ "$a" = "--no-lock" ] && continue
  ARGS+=("$a")
done
dotnet build Wop.Sdk.sln --nologo -v q
exec dotnet test Wop.Sdk.sln --no-build --nologo "${ARGS[@]+"${ARGS[@]}"}"
