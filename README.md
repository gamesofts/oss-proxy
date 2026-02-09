# OSS Reverse Proxy

一个用于阿里云 OSS 的反向代理服务。它接收客户端请求后，使用代理机当前时间重新签名，再转发到 OSS，从而规避客户端机器时间漂移（例如跨年测试）带来的签名失效问题。

## 特性

- 透明转发任意 OSS HTTP API（路径、方法、查询参数、请求体都保持原样）
- 使用代理服务器时间重建 `Date` 与 `Authorization`
- 支持透传 `x-oss-*` 头并纳入签名
- 支持多 bucket 路由：同一代理可按 bucket 使用不同 `endpoint/region/ak/sk`

## 运行

```bash
cat > config.json <<'JSON'
{
  "listenAddr": ":8080",
  "routes": [
    {
      "endpoint": "https://oss-cn-shanghai.aliyuncs.com",
      "region": "cn-shanghai",
      "accessKeyId": "your-ak-1",
      "accessKeySecret": "your-sk-1",
      "bucket": "bucket-a"
    },
    {
      "endpoint": "https://oss-cn-hangzhou.aliyuncs.com",
      "region": "cn-hangzhou",
      "accessKeyId": "your-ak-2",
      "accessKeySecret": "your-sk-2",
      "bucket": "bucket-b"
    }
  ]
}
JSON

go run .
```

## 使用方式

- 多 bucket 时：`http://proxy-host:8080/<bucket>/key`
- 单 bucket 时：仍兼容 `http://proxy-host:8080/key` 与 `http://proxy-host:8080/<bucket>/key`

代理会根据 bucket 自动选择对应路由并重建签名后转发。
