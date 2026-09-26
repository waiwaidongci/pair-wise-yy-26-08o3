# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

报告材料分为本人可见（`private`）和协调员专用（`coordinator`）。维护者默认只能看到自己上传的材料；协调员可以按报告成员对单份材料做逐人限时授权（`POST /api/grants`，写明到期日期），被授权人在到期前可读取该材料。到期、被撤销（`POST /api/grants/revoke`）或公告公开后，授权自动失效，再次读取即不可见；重新授权会覆盖旧期限并在 `evidence_grant_events` 中留下变更记录。报告详情中的 `grants.active` 与 `grants.expired` 分别展示仍在有效和已经结束的授权，协调员还能看到完整的 `grant_events` 变更流水。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告、维护者看不到协调员专用材料，以及逐人限时授权的授予、到期、撤销、重新授权覆盖期限与公开自动失效。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/grants`、`POST /api/grants/revoke`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`（可加 `as_of=YYYY-MM-DD` 模拟指定日期读取）
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。
