# shadowrocket-auto

自动收集公共节点并生成 **Shadowrocket（小火箭）** 订阅。

## 订阅地址

```
https://raw.githubusercontent.com/anna1211688/shadowrocket-auto/main/docs/shadowrocket.txt
```

复制以上链接 → 小火箭 → 配置 → 订阅 → 添加即可。

## 功能特点

- 多源自动拉取公共节点（带重试）
- 并行 TCP 连通性测试 + 延迟测量
- **严格过滤**：超时节点、高延迟节点、私有 IP
- 按延迟优先 + 协议权重排序（VLESS / Trojan 优先）
- 按「协议 + 主机 + 端口」精准去重
- 每小时自动更新（GitHub Actions）

## 过滤策略

| 条件 | 处理 |
|------|------|
| TCP 连接超过 3 秒 | 丢弃（超时） |
| 连通但延迟 > 2.5 秒 | 丢弃 |
| 私有/回环/保留 IP | 丢弃 |
| 最终保留 | 延迟最低的前 150 个节点 |

## 本地运行

```bash
pip install requests
python scripts/collector.py
```

运行后会生成：
- `docs/shadowrocket.txt` —— base64 订阅（给客户端用）
- `docs/shadowrocket_plain.txt` —— 明文节点列表（调试用）

## 配置说明

### 订阅源
`config/sources.txt`（每行一个 URL，支持 `#` 注释）

### 核心参数（`scripts/collector.py` 顶部）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `TIMEOUT` | 3.0 | TCP 连接超时（秒） |
| `MAX_LATENCY` | 2.5 | 最大可接受延迟（秒） |
| `MAX_NODES` | 150 | 最终保留节点数 |
| `MAX_WORKERS` | 50 | 并发测试数 |
| `SOURCE_RETRIES` | 1 | 源拉取失败重试次数 |

## License

MIT
