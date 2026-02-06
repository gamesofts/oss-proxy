# OSS Reverse Proxy

一个用于阿里云 OSS 的反向代理服务。它接收客户端请求后，使用代理机当前时间重新签名（OSS Signature V1），再转发到 OSS，从而规避客户端机器时间漂移（例如跨年测试）带来的签名失效问题。

## 特性

- 透明转发任意 OSS HTTP API（路径、方法、查询参数、请求体都保持原样）
- 使用代理服务器时间重建 `Date`/`x-oss-date` 与 `Authorization`
- 支持透传 `x-oss-*` 头并纳入签名
- 可选设置 `OSS_FORCE_BUCKET`，将所有请求强制路由到同一 bucket
- 可选 STS Token (`OSS_SECURITY_TOKEN`)
- 可选 `OSS_SIGNATURE_VERSION` 指定签名版本：`v1`/`v4`/`auto`（默认 auto）
- 支持通过 `OSS_CONFIG` 读取配置文件（JSON），环境变量会覆盖配置文件同名字段

## 运行

```bash
cat > oss-proxy.json <<'JSON'
{
  "listenAddr": ":8080",
  "endpoint": "oss-cn-hangzhou.aliyuncs.com",
  "region": "cn-hangzhou",
  "accessKeyId": "your-ak",
  "accessKeySecret": "your-sk",
  "securityToken": "",
  "forceBucket": "",
  "insecureUpstream": false,
  "signatureVersion": "auto"
}
JSON

export OSS_CONFIG=oss-proxy.json
# optional overrides
```

```bash
export OSS_ENDPOINT=oss-cn-hangzhou.aliyuncs.com
export OSS_ACCESS_KEY_ID=your-ak
export OSS_ACCESS_KEY_SECRET=your-sk
# optional
# export OSS_SECURITY_TOKEN=...
# export OSS_FORCE_BUCKET=my-bucket
# export OSS_REGION=cn-hangzhou
# export OSS_SIGNATURE_VERSION=auto
# export LISTEN_ADDR=:8080

go run .
```

## 使用方式

把测试客户端原本访问 OSS 的地址改为访问本服务：

- 原：`https://oss-cn-hangzhou.aliyuncs.com/bucket/key`
- 新：`http://proxy-host:8080/bucket/key`

代理会自动重建签名并转发到 `OSS_ENDPOINT`。

## 注意事项

- 本实现支持 OSS Signature V1 与 Signature V4，默认根据客户端头判断。
- 如你们使用了非常新的子资源参数，可在 `main.go` 的 `subresourceAllowlist` 中补充。
- 建议代理与 OSS 网络连通稳定，且代理机器时间与 NTP 同步。
