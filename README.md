# shadowrocket-auto

自动收集公共节点并生成 Shadowrocket（小火箭）订阅。

## 订阅地址

```
https://raw.githubusercontent.com/anna1211688/shadowrocket-auto/main/docs/shadowrocket.txt
```

直接复制以上链接到小火箭 → 配置 → 订阅 → 添加即可。

## 功能特点

- 多源自动拉取公共节点
- 并行 TCP 连通性测试 + 延迟排序
- 按协议+主机+端口精准去重
- 每小时自动更新（GitHub Actions）
- 只保留延迟最低的节点

## 本地运行

```bash
pip install requests
python scripts/collector.py
```

## 配置

- `config/sources.txt`：订阅源列表（每行一个 URL，支持 `#` 注释）
- `scripts/collector.py` 顶部可调整：
  - `MAX_NODES`：最终保留节点数量
  - `MAX_WORKERS`：并发测试数量
  - `TIMEOUT`：单个节点超时时间

## License

MIT
