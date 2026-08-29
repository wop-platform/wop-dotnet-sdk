Feature: WOP 商户接入网关全旅程
  商户使用 WOP .NET SDK 安全对接 WOP 网关：配置套件与密钥、发起 L0/L2 签名请求、
  校验平台响应与回调、拒收攻击报文。场景取自 spec F1-F9 与概念 API 的商户使用视角，
  tag 与 spec 条款一一对应（反向核对矩阵见 TEST-MATRIX.md）。

  Background:
    Given fixture 密钥已就绪

  @F1
  Scenario: 商户以 RSA3072 套件构建客户端
    When 商户以套件 "WOP-RSA3072-SHA256" 配置 RSA 密钥并构建客户端
    Then 客户端套件为 "WOP-RSA3072-SHA256"

  @F1
  Scenario: 商户以国密 SM2 套件构建客户端
    When 商户以套件 "WOP-SM2-SM3" 配置 SM2 密钥并构建客户端
    Then 客户端套件为 "WOP-SM2-SM3"

  @F1
  Scenario: 非法套件组合被明确拒绝
    When 商户尝试以套件 "WOP-RSA3072-SM3" 构建客户端
    Then 构建失败且错误码为 "SuiteUnsupported"

  @F1 @I6
  Scenario: 缺少必填配置被原子拒绝
    When 商户以空 appKey 构建客户端
    Then 构建失败且错误码为 "Config"

  @F2 @F3 @F4 @I1
  Scenario: 商户发起 L0 签名请求 digest 必产且入签
    Given RSA 客户端已构建
    When 商户构建 L0 请求 "POST" "/api/pay" 带 body
    Then 请求头含合法 x-wop-sign
    And x-wop-content-digest 已列入签名头
    And wireBody 为原文

  @F4 @D2
  Scenario: 无 body 请求 digest 缺席
    Given RSA 客户端已构建
    When 商户构建 L0 请求 "GET" "/api/query" 无 body
    Then 请求头不含 x-wop-content-digest

  @F2 @F9
  Scenario: 同输入请求幂等可重放
    Given RSA 客户端已构建
    When 商户两次构建相同 L0 请求 "POST" "/api/pay" 带 body
    Then 两次请求头与 wireBody 完全一致

  @F9
  Scenario: 出站 nonce 每次不同
    Given RSA 客户端已用默认随机源构建
    When 商户两次构建相同 L0 请求 "POST" "/api/pay" 带 body
    Then 两次 nonce 不同

  @F5
  Scenario: 商户发起 L2 加密请求
    Given RSA 客户端已构建
    When 商户构建 L2 请求 "POST" "/api/enc" 带 body
    Then wireBody 为 JSON 信封
    And 请求头含 x-wop-encrypt 指令头
    And x-wop-content-digest 基于信封字节而非原文

  @F6 @I2
  Scenario: 商户校验平台 L0 响应通过
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/pay" 签发 L0 响应
    When 商户校验该响应
    Then 校验通过且明文与响应体一致

  @F6 @I3
  Scenario: 商户校验平台 L2 响应并解密回原文
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/enc" 签发 L2 加密响应
    When 商户校验该响应
    Then 校验通过且解密明文为原文

  @F6 @I7
  Scenario: 商户拒收篡改签名的响应
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/pay" 签发 L0 响应
    And 攻击者篡改了响应签名
    When 商户校验该响应
    Then 校验失败且错误码为 "VerifyFailed"
    And 失败原因为固定模糊文案

  @F4 @D2
  Scenario: 商户拒收缺 digest 的有体响应
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/pay" 签发 L0 响应
    And 攻击者移除了 digest 头
    When 商户校验该响应
    Then 校验失败且错误码为 "DigestMismatch"

  @F6 @I5
  Scenario: 商户拒收跨族 digest 标签
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/pay" 签发跨族 digest 响应
    When 商户校验该响应
    Then 校验失败且错误码为 "Protocol"

  @F7 @D1
  Scenario: 商户拒收带填充的 base64url 签名
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/pay" 签发 L0 响应
    And 攻击者在签名段追加了填充字符
    When 商户校验该响应
    Then 校验失败且错误码为 "Protocol"

  @F6
  Scenario: 商户校验平台回调通过
    Given RSA 客户端已构建
    And 平台已按 "POST" "/callback/notify" 签发 L0 响应
    When 商户校验回调 "https://merchant.example.com/callback/notify?trace=1"
    Then 校验通过

  @F6
  Scenario: 非法回调 URL 被明确拒绝
    Given RSA 客户端已构建
    When 商户校验回调 "::::not-a-url"
    Then 校验失败且错误码为 "Protocol"

  @Q1
  Scenario: 商户一站式调用网关
    Given RSA 客户端已构建
    And 平台已按 "POST" "/api/pay" 签发 L0 响应
    When 商户通过可插拔 transport 一站式调用 "POST" "/api/pay" 带 body
    Then 调用结果校验通过
