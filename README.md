# 安全网关附件查杀服务（Secure Gateway AV Scan）

供应商附件进入内网前的恶意内容拦截网关。FastAPI + SQLite + 本地 ClamAV：
上传分块落盘后经**单条 IDSESSION TCP 连接**以 INSTREAM 送检，只有收到
干净回包的文件才开放下载。

## 架构

```
                ┌───────────────────────── docker compose ─────────────────────────┐
 浏览器/curl    │  api (FastAPI, 单进程)        adapter (可控转接器)      clamd     │
 ─────────────► │  :8000  ── 1 条 IDSESSION ──► :3311 ── 每请求一个 ──►  :3310    │
 /docs 演示     │  SQLite + 上传目录 (/data)     INSTREAM 会话             真实 ClamAV │
                │                      ▲        :8080 控制端点          离线特征库 │
                └──────────────────────┼─────────────────────────────────────────┘
                                       └── 乱序/延迟/断流 注入（演示用）
```

- **api**：唯一业务进程。全进程共用一条到 adapter 的 IDSESSION TCP 连接；
  最多 4 份在途，满额上传返回 503；每份从接纳扫描起总限 5 秒。
- **adapter**：协议转接 + 故障注入。把每个带请求号的 INSTREAM 转发为 clamd
  的标准 INSTREAM 会话，回包带请求号送回，可运行时配置乱序/延迟/断流。
- **clamd**：真实 ClamAV（`clamav/clamav:stable`），挂载离线演示特征库
  `clamd/eicar.hdb`（EICAR 测试串 MD5），`CLAMAV_NO_FRESHCLAM=true`，完全离线启动。

## 启动

```bash
docker compose up --build
# API:        http://localhost:8000/docs   (Swagger 交互演示)
# 转接器控制:  http://localhost:8080/config
```

## /docs 演示路径

1. **上传**：`POST /files` 选择 `samples/clean.txt` → 202 返回 `id`；
   轮询 `GET /files/{id}` 至 `status=clean`。
2. **下载**：`GET /files/{id}/download` → 200；命中或失败一律 403/409。
3. **命中**：上传 `samples/eicar.txt`（无害 EICAR 测试串）→ `infected`，
   `signature=Eicar-Test-Signature`，下载 403。
4. **取消**：先把转接器延迟调大（见下），上传后立即
   `POST /files/{id}/cancel` → `cancelled`；已开始送检的仍会送完分帧、
   回包被丢弃，名额保留到回包到达。
5. **满额 503**：延迟 2s 时并发上传 4 份后，第 5 份立即 503。
6. **超时/断流**：延迟 10s → 5s 总限触发，同连接未完成项全部 `failed`，
   自动重连；或 `drop_after_replies=1` 注入断流观察同样行为。
7. **重启**：`docker compose restart api` → 已发布（clean）文件仍可下载，
   未完项启动时被清扫为 `failed`。

一键脚本演示以上全部场景：

```bash
./scripts/demo.sh            # 需 curl + python3
```

端到端自检测试（22 项断言）：

```bash
python3 scripts/test_flows.py http://127.0.0.1:8000 http://127.0.0.1:8080
```

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/files` | 上传（multipart，≤8MiB 分块落盘）→ 202；在途满 4 份 → 503；超限 → 413 |
| GET  | `/files` | 列表 |
| GET  | `/files/{id}` | 扫描状态：`uploading/scanning/clean/infected/failed/cancelled` |
| POST | `/files/{id}` `/cancel` | 取消；终态 → 409 |
| GET  | `/files/{id}/download` | 仅 `clean` 可下载；进行中 409，其余 403 |

## 转接器控制（乱序/延迟/断流）

```bash
curl http://localhost:8080/config
curl -X POST http://localhost:8080/config -H 'Content-Type: application/json' -d '{
  "delay_min_ms": 0,        # 每回包随机延迟下限
  "delay_max_ms": 2000,     # 上限；窗口越大乱序越明显
  "drop_after_replies": 0,  # 第 N 个回包后断开会话（0=关）
  "drop_probability": 0.0   # 每个回包按概率断流
}'
```

## 连线协议（api ↔ adapter）

```
C: zIDSESSION\0                       S: SESSION <uuid> OK\n
C: zINSTREAM <reqid>\0 <len32><data>…<len32=0>
S: <reqid> stream: OK\n               # 回包可乱序，按 reqid 关联
S: <reqid> stream: <name> FOUND\n
S: <reqid> ERROR <msg>\n
```

同一文件的全部分帧在发送锁内一次性写完，不同文件正文绝不交叉；
adapter 将每个 INSTREAM 转发为 clamd 的标准会话并取回判定。

## 需求映射

| 要求 | 实现 |
|---|---|
| 每份 ≤8MiB，分块落盘后送检 | `main.py` 上传循环 512KiB 块写盘，超限 413；落盘完成后才 INSTREAM |
| 单进程共用一条 IDSESSION 连接 | `scanner.py` supervisor 维护唯一连接（uvicorn 必须单 worker） |
| 最多 4 份在途，满额 503 | `admit()` 名额计数，上传时准入 |
| 正文不交叉 | 每连接 `send_lock` 串行化整份 INSTREAM 分帧 |
| 乱序回包按请求号关联 | 进程内唯一 reqid，reader 按 reqid 分发 |
| 取消仍送完分帧、丢弃回包、收到前保留名额 | 发送循环不检查取消；reader 对 cancelled 任务丢弃回包并释放名额 |
| 每份总限 5 秒 | 接纳时设定 deadline，watchdog 50ms 巡检 |
| 超时/断流 → 同连接未完成项全失败、清理后重连、旧任务不影响新连接 | watchdog/reader 触发连接回收，按代（gen）清理后重连；reqid 进程唯一 |
| 仅干净回包可下载 | 下载端点仅放行 `clean` |
| 重启保留已发布、未完项失败 | SQLite + 上传目录挂卷；启动清扫 `uploading/scanning → failed` |
| 离线特征库/无害样例/可控转接器 | `clamd/eicar.hdb`、`samples/eicar.txt`、adapter `:8080/config` |

## 本地开发（无 Docker）

adapter 内置 mock 后端，直接按 `adapter/eicar.hdb` 的 MD5 特征判定：

```bash
SCAN_BACKEND=mock python3 adapter/adapter.py &          # :3311 + :8080
cd api && DATA_DIR=/tmp/gwdata SCANNER_HOST=127.0.0.1 \
  python3 -m uvicorn app.main:app --port 8000 &          # 需 fastapi/uvicorn
python3 scripts/test_flows.py
```

## 说明与限制

- 必须单进程运行（连接与名额是进程内状态）；水平扩容需按进程隔离连接。
- 5 秒总限自“接纳扫描”起算，包含上传接收时间；慢速上传会挤占扫描预算。
- 超时即回收整条连接（同连接未完成项全部失败），这是协议要求的行为。
- `clamav/clamav:stable` 镜像离线启动依赖其 `CLAMAV_NO_FRESHCLAM` 开关；
  如需换版本，任意近期 tag 均可。
