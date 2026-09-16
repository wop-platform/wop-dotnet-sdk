using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Wop.Sdk;

/// <summary>配置 JSON 解析（K8/K21）：Utf8JsonReader 预扫重复键后 Deserialize + §3.4 校验。</summary>
internal static class ConfigJsonParser
{
    private static readonly JsonSerializerOptions DeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
        AllowTrailingCommas = false,
    };

    /// <summary>解析 UTF-8 JSON 文本为不可变配置快照。</summary>
    internal static WopSdkConfig Parse(string json)
    {
        if (json == null)
        {
            throw Config("配置文件 JSON 解析失败: 空内容");
        }

        var trimmed = StripBom(json.Trim());
        if (trimmed.Length == 0)
        {
            throw Config("配置文件 JSON 解析失败: 空文件");
        }

        var utf8 = Encoding.UTF8.GetBytes(trimmed);
        DuplicateKeyPrescanner.Scan(utf8);

        WopSdkConfigJson dto;
        try
        {
            dto = JsonSerializer.Deserialize<WopSdkConfigJson>(utf8, DeserializeOptions)
                  ?? throw Config("配置文件 JSON 解析失败: 根节点非对象");
        }
        catch (JsonException e)
        {
            throw Config("配置文件 JSON 解析失败: " + e.Message);
        }

        var http = dto.HttpClient == null
            ? HttpClientSettings.Defaults
            : new HttpClientSettings(
                dto.HttpClient.ConnectTimeout ?? HttpClientSettings.DefaultConnectTimeout,
                dto.HttpClient.ReadTimeout ?? HttpClientSettings.DefaultReadTimeout,
                dto.HttpClient.MaxRetryCount ?? HttpClientSettings.DefaultMaxRetryCount);

        var raw = new WopSdkConfig(
            dto.AppKey ?? "",
            dto.Suite ?? "",
            dto.MerchantPrivateKey ?? "",
            dto.PlatformPublicKey ?? "",
            dto.ServerRoot ?? "",
            dto.BackupServerRoots ?? Array.Empty<string>(),
            dto.ExpiredSeconds ?? WopSignProtocol.ExpiredSecondsDefault,
            http,
            null);

        return ConfigValidator.ValidateAndNormalize(raw);
    }

    private static string StripBom(string text) =>
        text.StartsWith("\uFEFF", StringComparison.Ordinal) ? text.Substring(1) : text;

    private static WopException Config(string message) =>
        new(WopErrorCode.Config, message);

    /// <summary>Utf8JsonReader 预扫对象键，遇重复键即 fail-fast（§4.4 K21）。</summary>
    private static class DuplicateKeyPrescanner
    {
        internal static void Scan(ReadOnlySpan<byte> utf8Json)
        {
            var reader = new Utf8JsonReader(utf8Json, new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw Config("配置文件 JSON 解析失败: 根节点须为对象");
            }
            ScanObject(ref reader, nestedHttpClient: false);
        }

        private static void ScanObject(ref Utf8JsonReader reader, bool nestedHttpClient)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return;
                }
                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw Config("配置文件 JSON 解析失败: 对象结构非法");
                }

                var key = reader.GetString() ?? "";
                if (!keys.Add(key))
                {
                    throw Config("配置字段 " + key + " 重复: " + key);
                }

                if (!reader.Read())
                {
                    throw Config("配置文件 JSON 解析失败: 意外结束");
                }

                if (!nestedHttpClient && key == "httpClient")
                {
                    if (reader.TokenType != JsonTokenType.StartObject)
                    {
                        throw Config("配置字段 httpClient 类型非法: 期望对象");
                    }
                    ScanObject(ref reader, nestedHttpClient: true);
                }
                else if (nestedHttpClient && reader.TokenType == JsonTokenType.StartObject)
                {
                    throw Config("配置字段 httpClient 类型非法: 不支持更深嵌套");
                }
                else
                {
                    SkipValue(ref reader);
                }
            }
            throw Config("配置文件 JSON 解析失败: 对象未闭合");
        }

        private static void SkipValue(ref Utf8JsonReader reader)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.String:
                case JsonTokenType.Number:
                case JsonTokenType.True:
                case JsonTokenType.False:
                case JsonTokenType.Null:
                    return;
                case JsonTokenType.StartObject:
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndObject)
                        {
                            return;
                        }
                        if (reader.TokenType != JsonTokenType.PropertyName)
                        {
                            throw Config("配置文件 JSON 解析失败: 对象结构非法");
                        }
                        if (!reader.Read())
                        {
                            throw Config("配置文件 JSON 解析失败: 意外结束");
                        }
                        SkipValue(ref reader);
                    }
                    throw Config("配置文件 JSON 解析失败: 对象未闭合");
                case JsonTokenType.StartArray:
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndArray)
                        {
                            return;
                        }
                        SkipValue(ref reader);
                    }
                    throw Config("配置文件 JSON 解析失败: 数组未闭合");
                default:
                    throw Config("配置文件 JSON 解析失败: 非法 token");
            }
        }
    }

    private sealed class WopSdkConfigJson
    {
        [JsonPropertyName("appKey")]
        public string? AppKey { get; set; }

        [JsonPropertyName("suite")]
        public string? Suite { get; set; }

        [JsonPropertyName("merchantPrivateKey")]
        public string? MerchantPrivateKey { get; set; }

        [JsonPropertyName("platformPublicKey")]
        public string? PlatformPublicKey { get; set; }

        [JsonPropertyName("serverRoot")]
        public string? ServerRoot { get; set; }

        [JsonPropertyName("backupServerRoots")]
        public List<string>? BackupServerRoots { get; set; }

        [JsonPropertyName("expiredSeconds")]
        public long? ExpiredSeconds { get; set; }

        [JsonPropertyName("httpClient")]
        public HttpClientSettingsJson? HttpClient { get; set; }
    }

    private sealed class HttpClientSettingsJson
    {
        [JsonPropertyName("connectTimeout")]
        public int? ConnectTimeout { get; set; }

        [JsonPropertyName("readTimeout")]
        public int? ReadTimeout { get; set; }

        [JsonPropertyName("maxRetryCount")]
        public int? MaxRetryCount { get; set; }
    }
}
