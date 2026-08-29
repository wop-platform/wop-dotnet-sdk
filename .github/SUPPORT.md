# 支持与发布渠道（Channels）

| 渠道 | 地址 | 说明 |
|---|---|---|
| **NuGet 发布** | https://www.nuget.org/packages/Wop.Sdk/ | 官方发布渠道；`dotnet add package Wop.Sdk` |
| 规格真源 | https://github.com/wop-platform/wop-specs | wop-sdk-spec / crypto-strategy-spec / crypto-vectors 唯一维护版（变更经 PR） |
| 问题反馈 | https://github.com/wop-platform/wop-dotnet-sdk/issues | Bug / 集成问题 / 功能请求 |
| 安全披露 | https://github.com/wop-platform/wop-dotnet-sdk/security/advisories/new | 漏洞请勿开公开 Issue，走私下披露 |
| CI 状态 | https://github.com/wop-platform/wop-dotnet-sdk/actions | ci（门禁 98% 行+分支）/ release（tag 触发发版） |

> 版本策略：conventional commits；`v*` tag 触发 release 工作流（验证段全绿 → pack → NuGet 发布）。
