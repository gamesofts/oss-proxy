# OSS Reverse Proxy

一个用于阿里云 OSS 的反向代理服务。它接收客户端请求后，使用代理机当前时间重新签名（OSS Signature V1），再转发到 OSS，从而规避客户端机器时间漂移（例如跨年测试）带来的签名失效问题。

## 特性

- 透明转发任意 OSS HTTP API（路径、方法、查询参数、请求体都保持原样）
- 使用代理服务器时间重建 `Date` 与 `Authorization`
- 支持透传 `x-oss-*` 头并纳入签名

## 运行

```bash
cat > config.json <<'JSON'
{
  "listenAddr": ":8080",
  "endpoint": "oss-cn-hangzhou.aliyuncs.com",
  "bucket": "your-bucket",
  "region": "cn-hangzhou",
  "accessKeyId": "your-ak",
  "accessKeySecret": "your-sk"
}
JSON

go run .
```

## 使用方式

- 原：`https://oss-cn-hangzhou.aliyuncs.com/your-bucket/key`
- 新：`http://proxy-host:8080/key`（或 `http://proxy-host:8080/your-bucket/key`）

代理会自动重建签名并转发到 `endpoint`。
