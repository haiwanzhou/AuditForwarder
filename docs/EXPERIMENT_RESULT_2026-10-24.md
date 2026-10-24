# 合谋危害定级报告

- 生成时间：2026-10-24T06:18:07Z
- 统计区间：最近 7 天（自 2026-10-17T06:18:07Z 起）
- 风险事件总数：7（HIGH=6 / MID=0 / LOW=1 / 其他=0）
- 涉及规则数：6

## 规则汇总

| 规则 | 命中次数 | 最高等级 | 最高评分 |
|------|----------|----------|----------|
| R-001 备份销毁合谋 | 2 | HIGH | 100 |
| R-002 密钥权限拆分绕过 | 1 | HIGH | 98 |
| R-003 配置篡改链路 | 1 | HIGH | 88 |
| R-004 数据批量外泄 | 1 | HIGH | 100 |
| R-005 权限晋升合谋 | 1 | HIGH | 98 |
| 未命中规则 | 1 | LOW | 25 |

## 规则 R-001 备份销毁合谋

- 命中次数：2

### 事件 ce-718c8f23e08c8198（HIGH / 100 分）

- 证据规则：R-001 备份销毁合谋
- 涉及操作员：admin, admin2, admin3（3 人）
- 资产组：backup-group
- 时间窗：2026-10-24T06:15:00Z ~ 2026-10-24T06:30:00Z
- 评分构成：规则 90 / 画像 13 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:15:57Z | admin | lab-pc | network/read | /api/storage/volume | GET 127.0.0.1:18080/api/storage/volume status=200 req_len=0 |
| 2026-10-24T06:15:57Z | admin | lab-pc | network/write | /api/storage/volume/1/mount | PATCH 127.0.0.1:18080/api/storage/volume/1/mount status=200 req_len=0 |
| 2026-10-24T06:15:57Z | admin | lab-pc | network/create | /api/backup | POST 127.0.0.1:18080/api/backup status=201 req_len=28 |
| 2026-10-24T06:15:58Z | admin | lab-pc | network/create | /api/snapshot | POST 127.0.0.1:18080/api/snapshot status=201 req_len=30 |
| 2026-10-24T06:15:58Z | admin | lab-pc | network/delete | /api/backup/lab_r00122557.db | DELETE 127.0.0.1:18080/api/backup/lab_r00122557.db status=200 req_len=0 |
| 2026-10-24T06:15:58Z | admin2 | lab-pc | network/read | /api/storage/volume | GET 127.0.0.1:18080/api/storage/volume status=200 req_len=0 |
| 2026-10-24T06:15:58Z | admin2 | lab-pc | network/write | /api/storage/volume/1/unmount | PATCH 127.0.0.1:18080/api/storage/volume/1/unmount status=200 req_len=0 |
| 2026-10-24T06:15:58Z | admin3 | lab-pc | network/delete | /api/snapshot/lab_r00122557.snap | DELETE 127.0.0.1:18080/api/snapshot/lab_r00122557.snap status=200 req_len=0 |

### 事件 ce-d0ac4dac0c2421a8（HIGH / 100 分）

- 证据规则：R-001 备份销毁合谋
- 涉及操作员：admin, admin2, admin3（3 人）
- 资产组：backup-group
- 时间窗：2026-10-24T06:00:00Z ~ 2026-10-24T06:15:00Z
- 评分构成：规则 90 / 画像 25 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:13:19Z | admin | lab-pc | network/create | /api/backup | POST 127.0.0.1:18080/api/backup status=201 req_len=28 |
| 2026-10-24T06:13:19Z | admin | lab-pc | network/create | /api/snapshot | POST 127.0.0.1:18080/api/snapshot status=201 req_len=30 |
| 2026-10-24T06:13:19Z | admin | lab-pc | network/delete | /api/backup/lab_r00122399.db | DELETE 127.0.0.1:18080/api/backup/lab_r00122399.db status=200 req_len=0 |
| 2026-10-24T06:13:19Z | admin2 | lab-pc | network/read | /api/storage/volume | GET 127.0.0.1:18080/api/storage/volume status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/read | /api/storage/volume | GET 127.0.0.1:18080/api/storage/volume status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/write | /api/storage/volume/1/mount | PATCH 127.0.0.1:18080/api/storage/volume/1/mount status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/write | /api/storage/volume/2/mount | PATCH 127.0.0.1:18080/api/storage/volume/2/mount status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/create | /api/backup | POST 127.0.0.1:18080/api/backup status=201 req_len=28 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/create | /api/snapshot | POST 127.0.0.1:18080/api/snapshot status=201 req_len=30 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/delete | /api/backup/lab_r00122424.db | DELETE 127.0.0.1:18080/api/backup/lab_r00122424.db status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin2 | lab-pc | network/read | /api/storage/volume | GET 127.0.0.1:18080/api/storage/volume status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin2 | lab-pc | network/write | /api/storage/volume/1/unmount | PATCH 127.0.0.1:18080/api/storage/volume/1/unmount status=200 req_len=0 |
| 2026-10-24T06:13:46Z | admin3 | lab-pc | network/delete | /api/snapshot/lab_r00122424.snap | DELETE 127.0.0.1:18080/api/snapshot/lab_r00122424.snap status=200 req_len=0 |

## 规则 R-002 密钥权限拆分绕过

- 命中次数：1

### 事件 ce-836e2dddbdeee099（HIGH / 98 分）

- 证据规则：R-002 密钥权限拆分绕过
- 涉及操作员：admin, admin2, admin3（3 人）
- 资产组：key-mgmt-group
- 时间窗：2026-10-24T06:15:00Z ~ 2026-10-24T06:30:00Z
- 评分构成：规则 85 / 画像 13 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:16:27Z | admin | lab-pc | network/create | /api/key | POST 127.0.0.1:18080/api/key status=201 req_len=25 |
| 2026-10-24T06:16:27Z | admin2 | lab-pc | network/create | /api/key/4/distribute | POST 127.0.0.1:18080/api/key/4/distribute status=200 req_len=20 |
| 2026-10-24T06:16:28Z | admin3 | lab-pc | network/delete | /api/key/audit/clear | DELETE 127.0.0.1:18080/api/key/audit/clear status=200 req_len=0 |

## 规则 R-003 配置篡改链路

- 命中次数：1

### 事件 ce-fd49387f7d5ecca4（HIGH / 88 分）

- 证据规则：R-003 配置篡改链路
- 涉及操作员：admin, admin2, admin3（3 人）
- 资产组：sys-config-group
- 时间窗：2026-10-24T06:15:00Z ~ 2026-10-24T06:30:00Z
- 评分构成：规则 75 / 画像 13 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:16:32Z | admin | lab-pc | network/write | /api/system/config | PUT 127.0.0.1:18080/api/system/config status=200 req_len=45 |
| 2026-10-24T06:16:33Z | admin2 | lab-pc | network/create | /api/system/service/restart | POST 127.0.0.1:18080/api/system/service/restart status=200 req_len=0 |
| 2026-10-24T06:16:33Z | admin3 | lab-pc | network/delete | /api/system/logs/clear | DELETE 127.0.0.1:18080/api/system/logs/clear status=200 req_len=0 |

## 规则 R-004 数据批量外泄

- 命中次数：1

### 事件 ce-c050352b66224f84（HIGH / 100 分）

- 证据规则：R-004 数据批量外泄
- 涉及操作员：admin, admin2, admin3（3 人）
- 资产组：db-group
- 时间窗：2026-10-24T06:15:00Z ~ 2026-10-24T06:30:00Z
- 评分构成：规则 87 / 画像 13 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:16:16Z | admin | lab-pc | network/read | /api/books | GET 127.0.0.1:18080/api/books status=200 req_len=0 |
| 2026-10-24T06:16:16Z | admin | lab-pc | network/delete | /api/books/20 | DELETE 127.0.0.1:18080/api/books/20 status=200 req_len=0 |
| 2026-10-24T06:16:38Z | admin | lab-pc | network/write | /api/users/3/privilege | PATCH 127.0.0.1:18080/api/users/3/privilege status=200 req_len=23 |
| 2026-10-24T06:16:38Z | admin2 | lab-pc | network/read | /api/books/export | GET 127.0.0.1:18080/api/books/export status=200 req_len=0 |
| 2026-10-24T06:16:39Z | admin3 | lab-pc | network/delete | /api/books/audit/clear | DELETE 127.0.0.1:18080/api/books/audit/clear status=200 req_len=0 |

## 规则 R-005 权限晋升合谋

- 命中次数：1

### 事件 ce-f9bb7c9966ad434e（HIGH / 98 分）

- 证据规则：R-005 权限晋升合谋
- 涉及操作员：admin, admin2, admin3, lab_backdoor_r00522608（4 人）
- 资产组：general-group
- 时间窗：2026-10-24T06:15:00Z ~ 2026-10-24T06:30:00Z
- 评分构成：规则 85 / 画像 13 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:50311 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:53536 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:60673 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:53259 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:56467 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:58840 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:60112 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:61623 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49675 -> 127.0.0.1:49676 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49676 -> 127.0.0.1:49675 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49677 -> 127.0.0.1:49678 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49678 -> 127.0.0.1:49677 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49711 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49712 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50311 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50651 -> 127.0.0.1:56818 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.150.72.129 | tcp 10.4.55.6:50883 -> 36.150.72.129:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50928 -> 127.0.0.1:64732 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 111.29.14.203 | tcp 10.4.55.6:50930 -> 111.29.14.203:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 1.12.12.12 | tcp 10.4.55.6:51016 -> 1.12.12.12:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53259 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:53269 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 120.53.53.53 | tcp 10.4.55.6:53313 -> 120.53.53.53:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:53341 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 52.130.198.230 | tcp 10.4.55.6:53385 -> 52.130.198.230:443 state=5 proc=MSPCManager.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 104.17.184.35 | tcp 10.4.55.6:53411 -> 104.17.184.35:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 141.193.213.150 | tcp 10.4.55.6:53452 -> 141.193.213.150:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 141.193.213.119 | tcp 10.4.55.6:53464 -> 141.193.213.119:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 180.184.103.12 | tcp 10.4.55.6:53507 -> 180.184.103.12:80 state=5 proc=wpscloudsvr.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53524 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53536 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53615 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53616 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53617 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53701 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54324 -> 127.0.0.1:54340 state=5 proc=steam.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54326 -> 127.0.0.1:54339 state=5 proc=steam.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54339 -> 127.0.0.1:54326 state=5 proc=steamwebhelper.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54340 -> 127.0.0.1:54324 state=5 proc=steamwebhelper.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54533 -> 127.0.0.1:54891 state=5 proc=ECAgent.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.159.70.71 | tcp 10.4.55.6:54693 -> 36.159.70.71:443 state=5 proc=node.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54891 -> 127.0.0.1:54533 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54892 -> 127.0.0.1:54893 state=5 proc=ECAgent.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54893 -> 127.0.0.1:54892 state=5 proc=ECAgent.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 45.121.184.101 | tcp 10.4.55.6:54902 -> 45.121.184.101:27020 state=5 proc=steam.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 188.245.202.112 | tcp 10.4.55.6:55317 -> 188.245.202.112:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 47.102.205.24 | tcp 10.4.55.6:55381 -> 47.102.205.24:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:55615 -> 127.0.0.1:64732 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 124.70.93.189 | tcp 10.4.55.6:55903 -> 124.70.93.189:11111 state=5 proc=wpscloudsvr.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56467 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:49711 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:49712 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:53524 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:56901 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56818 -> 127.0.0.1:50651 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56893 -> 127.0.0.1:56894 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56894 -> 127.0.0.1:56893 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56895 -> 127.0.0.1:56896 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56896 -> 127.0.0.1:56895 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56901 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 223.6.6.6 | tcp 10.4.55.6:57448 -> 223.6.6.6:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:57449 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.159.70.71 | tcp 10.4.55.6:57898 -> 36.159.70.71:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 4.145.79.82 | tcp 10.4.55.6:58728 -> 4.145.79.82:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.155.182.76 | tcp 10.4.55.6:58754 -> 36.155.182.76:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58840 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 141.95.64.200 | tcp 10.4.55.6:59861 -> 141.95.64.200:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:60112 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:60673 -> 127.0.0.1:7897 state=5 proc=steamwebhelper.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:61623 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 157.180.32.230 | tcp 10.4.55.6:61703 -> 157.180.32.230:443 state=5 |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:63106 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 39.173.157.69 | tcp 10.4.55.6:63633 -> 39.173.157.69:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:63685 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 112.13.210.71 | tcp 10.4.55.6:63703 -> 112.13.210.71:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64732 -> 127.0.0.1:50928 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64732 -> 127.0.0.1:55615 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64732 -> 127.0.0.1:64733 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64733 -> 127.0.0.1:64732 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:64766 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:64767 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:47Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:64768 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:51Z | admin | lab-pc | network/connect | 111.29.14.203 | tcp 10.4.55.6:53550 -> 111.29.14.203:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:51Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53553 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:15:51Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:53553 state=5 |
| 2026-10-24T06:15:53Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:53558 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:15:55Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:8443 -> 127.0.0.1:53582 state=5 proc=auditforwarder-server.exe |
| 2026-10-24T06:15:55Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53582 -> 127.0.0.1:8443 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:15:57Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53588 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:15:57Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:53588 state=5 |
| 2026-10-24T06:15:57Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:15:57Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:15:58Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:15:58Z | admin3 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:15:59Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:53627 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:01Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53655 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:01Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:53655 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:56566 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:57796 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:57916 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:62184 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56566 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 101.126.75.33 | tcp 10.4.55.6:56569 -> 101.126.75.33:443 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57796 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 111.31.99.164 | tcp 10.4.55.6:57797 -> 111.31.99.164:443 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57916 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:57917 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 223.6.6.6 | tcp 10.4.55.6:57918 -> 223.6.6.6:443 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:62184 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 119.3.170.185 | tcp 10.4.55.6:62187 -> 119.3.170.185:443 state=5 |
| 2026-10-24T06:16:03Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:62188 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:16:05Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:57809 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:07Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:57826 state=5 |
| 2026-10-24T06:16:07Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57826 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:09Z | admin | lab-pc | network/connect | 140.82.113.22 | tcp 10.4.55.6:57849 -> 140.82.113.22:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:11Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:57863 state=5 |
| 2026-10-24T06:16:11Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57863 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:15Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:57888 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:16Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:16:16Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:16:17Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:57896 state=5 |
| 2026-10-24T06:16:17Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57896 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:21Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:57932 state=5 |
| 2026-10-24T06:16:21Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57932 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:23Z | admin | lab-pc | network/connect | 111.29.14.203 | tcp 10.4.55.6:57938 -> 111.29.14.203:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:23Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:57941 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:8888 -> 127.0.0.1:57955 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:18080 -> 127.0.0.1:57956 state=5 proc=python.exe |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:57950 state=5 |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57950 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57955 -> 127.0.0.1:8888 state=5 proc=python.exe |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57956 -> 127.0.0.1:18080 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:16:27Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:16:27Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:27Z | admin3 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:29Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:57975 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:58660 state=5 |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:57168 state=5 |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:58655 state=5 |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58668 state=5 |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57168 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58655 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58660 -> 127.0.0.1:7897 state=5 |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 120.253.250.226 | tcp 10.4.55.6:58662 -> 120.253.250.226:80 state=5 |
| 2026-10-24T06:16:31Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58668 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:32Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:16:32Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:16:33Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:33Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:8888 -> 127.0.0.1:58714 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:16:33Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:18080 -> 127.0.0.1:58715 state=5 proc=python.exe |
| 2026-10-24T06:16:33Z | admin | lab-pc | network/connect | 58.216.46.5 | tcp 10.4.55.6:58674 -> 58.216.46.5:80 state=5 |
| 2026-10-24T06:16:33Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58714 -> 127.0.0.1:8888 state=5 proc=python.exe |
| 2026-10-24T06:16:33Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58715 -> 127.0.0.1:18080 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:16:33Z | admin3 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:37Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58736 state=5 |
| 2026-10-24T06:16:37Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58736 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:37Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:58738 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:38Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:16:38Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:16:38Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:39Z | admin3 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:41Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58780 state=5 |
| 2026-10-24T06:16:41Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:58776 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:41Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58780 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:45Z | admin | lab-pc | network/connect | 140.82.113.22 | tcp 10.4.55.6:58792 -> 140.82.113.22:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:16:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58795 state=5 |
| 2026-10-24T06:16:47Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58795 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:16:48Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:16:48Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:16:49Z | admin | lab-pc | network/create | /api/admin/user | POST 127.0.0.1:18080/api/admin/user status=201 req_len=80 |
| 2026-10-24T06:16:49Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:8888 -> 127.0.0.1:58814 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:16:49Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:18080 -> 127.0.0.1:58815 state=5 proc=python.exe |
| 2026-10-24T06:16:49Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58814 -> 127.0.0.1:8888 state=5 proc=python.exe |
| 2026-10-24T06:16:49Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58815 -> 127.0.0.1:18080 state=5 proc=auditforwarder-client.exe |
| 2026-10-24T06:16:49Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:16:49Z | admin2 | lab-pc | network/create | /api/admin/user/9/assign-admin | POST 127.0.0.1:18080/api/admin/user/9/assign-admin status=200 req_len=0 |
| 2026-10-24T06:16:49Z | lab_backdoor_r00522608 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=62 |
| 2026-10-24T06:16:49Z | lab_backdoor_r00522608 | lab-pc | network/create | /api/admin/exec | POST 127.0.0.1:18080/api/admin/exec status=200 req_len=25 |

## 规则 未命中规则

- 命中次数：1

### 事件 ce-9538b6cb77503f1a（LOW / 25 分）

- 证据规则：
- 涉及操作员：admin, admin2, admin3（3 人）
- 资产组：general-group
- 时间窗：2026-10-24T06:00:00Z ~ 2026-10-24T06:15:00Z
- 评分构成：规则 0 / 画像 25 / ML 0 / 图 0
- 评分说明：无关联工单

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|------|--------|------|------|------|------|
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:50311 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:53536 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:60673 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:63643 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:56467 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:58478 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:60112 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:61623 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:9097 -> 127.0.0.1:63051 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49675 -> 127.0.0.1:49676 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49676 -> 127.0.0.1:49675 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49677 -> 127.0.0.1:49678 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49678 -> 127.0.0.1:49677 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49711 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:49712 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50311 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:50319 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50321 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.150.72.129 | tcp 10.4.55.6:50883 -> 36.150.72.129:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50928 -> 127.0.0.1:64732 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 111.29.14.203 | tcp 10.4.55.6:50930 -> 111.29.14.203:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 1.12.12.12 | tcp 10.4.55.6:51016 -> 1.12.12.12:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:53536 -> 127.0.0.1:7897 state=5 proc=chrome.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53615 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53616 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53617 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:53701 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54324 -> 127.0.0.1:54340 state=5 proc=steam.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54326 -> 127.0.0.1:54339 state=5 proc=steam.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54339 -> 127.0.0.1:54326 state=5 proc=steamwebhelper.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54340 -> 127.0.0.1:54324 state=5 proc=steamwebhelper.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54533 -> 127.0.0.1:54891 state=5 proc=ECAgent.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.159.70.71 | tcp 10.4.55.6:54693 -> 36.159.70.71:443 state=5 proc=node.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54891 -> 127.0.0.1:54533 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54892 -> 127.0.0.1:54893 state=5 proc=ECAgent.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:54893 -> 127.0.0.1:54892 state=5 proc=ECAgent.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 45.121.184.101 | tcp 10.4.55.6:54902 -> 45.121.184.101:27020 state=5 proc=steam.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 120.133.65.238 | tcp 10.4.55.6:55146 -> 120.133.65.238:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 159.27.21.167 | tcp 10.4.55.6:55153 -> 159.27.21.167:443 state=5 proc=MSPCManagerCore.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 188.245.202.112 | tcp 10.4.55.6:55317 -> 188.245.202.112:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 47.102.205.24 | tcp 10.4.55.6:55381 -> 47.102.205.24:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:55615 -> 127.0.0.1:64732 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 124.70.93.189 | tcp 10.4.55.6:55903 -> 124.70.93.189:11111 state=5 proc=wpscloudsvr.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56467 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:49711 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:49712 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50321 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:56901 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56893 -> 127.0.0.1:56894 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56894 -> 127.0.0.1:56893 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56895 -> 127.0.0.1:56896 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56896 -> 127.0.0.1:56895 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56901 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.159.70.71 | tcp 10.4.55.6:57898 -> 36.159.70.71:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58478 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 4.145.79.82 | tcp 10.4.55.6:58728 -> 4.145.79.82:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.155.182.76 | tcp 10.4.55.6:58754 -> 36.155.182.76:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 141.95.64.200 | tcp 10.4.55.6:59861 -> 141.95.64.200:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:60112 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:60673 -> 127.0.0.1:7897 state=5 proc=steamwebhelper.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:61623 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 157.180.32.230 | tcp 10.4.55.6:61703 -> 157.180.32.230:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:63051 -> 127.0.0.1:9097 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.17 | tcp 10.4.55.6:63106 -> 36.151.170.17:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:63502 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:63505 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 223.6.6.6 | tcp 10.4.55.6:63506 -> 223.6.6.6:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 39.173.157.69 | tcp 10.4.55.6:63633 -> 39.173.157.69:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:63643 -> 127.0.0.1:7897 state=5 proc=OneDrive.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 40.79.163.155 | tcp 10.4.55.6:63644 -> 40.79.163.155:443 state=5 |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:63678 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 112.13.210.71 | tcp 10.4.55.6:63679 -> 112.13.210.71:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:63680 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:63685 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 112.13.210.71 | tcp 10.4.55.6:63703 -> 112.13.210.71:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64732 -> 127.0.0.1:50928 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64732 -> 127.0.0.1:55615 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64732 -> 127.0.0.1:64733 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:64733 -> 127.0.0.1:64732 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:64766 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:64767 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:10Z | admin | lab-pc | network/connect | 36.151.170.45 | tcp 10.4.55.6:64768 -> 36.151.170.45:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:12Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50330 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:12Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50330 state=5 |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50361 -> 127.0.0.1:56818 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 112.13.210.71 | tcp 10.4.55.6:50362 -> 112.13.210.71:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50365 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:50366 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50371 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50365 state=5 |
| 2026-10-24T06:13:16Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56818 -> 127.0.0.1:50361 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:19Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:13:19Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:13:19Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:13:20Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50414 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:20Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50414 state=5 |
| 2026-10-24T06:13:26Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50445 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:26Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50445 state=5 |
| 2026-10-24T06:13:28Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50464 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:30Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50478 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:30Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50478 state=5 |
| 2026-10-24T06:13:34Z | admin | lab-pc | network/connect | 140.82.113.22 | tcp 10.4.55.6:50505 -> 140.82.113.22:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:36Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50510 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:36Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50511 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:36Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50514 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:36Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50511 state=5 |
| 2026-10-24T06:13:40Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50522 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:13:40Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50523 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:40Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50523 state=5 |
| 2026-10-24T06:13:44Z | admin | lab-pc | network/read | / | GET 127.0.0.1:18080/ status=200 req_len=0 |
| 2026-10-24T06:13:45Z | admin | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=45 |
| 2026-10-24T06:13:45Z | admin2 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:13:46Z | admin3 | lab-pc | network/create | /api/auth/login | POST 127.0.0.1:18080/api/auth/login status=200 req_len=46 |
| 2026-10-24T06:13:46Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50562 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:46Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50562 state=5 |
| 2026-10-24T06:13:50Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50592 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:50Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50592 state=5 |
| 2026-10-24T06:13:56Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50604 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:13:56Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50604 state=5 |
| 2026-10-24T06:13:58Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50612 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:00Z | admin | lab-pc | network/connect | 36.150.72.129 | tcp 10.4.55.6:50618 -> 36.150.72.129:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:00Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50619 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:00Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50619 state=5 |
| 2026-10-24T06:14:02Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:50620 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:02Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:50625 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:06Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50638 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:06Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50638 state=5 |
| 2026-10-24T06:14:08Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50648 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50651 -> 127.0.0.1:56818 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:10Z | admin | lab-pc | network/connect | 140.82.113.22 | tcp 10.4.55.6:50652 -> 140.82.113.22:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50655 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50655 state=5 |
| 2026-10-24T06:14:10Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56818 -> 127.0.0.1:50651 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:16Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:50671 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:16Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50672 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:16Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50672 state=5 |
| 2026-10-24T06:14:19Z | admin | lab-pc | registry/set | SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | registry change: SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce |
| 2026-10-24T06:14:20Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50684 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:20Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50684 state=5 |
| 2026-10-24T06:14:26Z | admin | lab-pc | network/connect | 36.150.72.129 | tcp 10.4.55.6:50694 -> 36.150.72.129:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:26Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:50695 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:26Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:50695 state=5 |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:57990 state=5 |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57990 -> 127.0.0.1:7897 state=5 proc=msedge.exe |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 4.150.223.110 | tcp 10.4.55.6:57991 -> 4.150.223.110:443 state=5 |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 223.6.6.6 | tcp 10.4.55.6:57994 -> 223.6.6.6:443 state=5 |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:57997 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:57998 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:14:28Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:57999 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:30Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58010 state=5 |
| 2026-10-24T06:14:30Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58010 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:34Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:58021 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:34Z | admin | lab-pc | network/connect | 111.29.14.203 | tcp 10.4.55.6:58022 -> 111.29.14.203:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:34Z | admin | lab-pc | network/connect | 1.15.160.109 | tcp 10.4.55.6:58023 -> 1.15.160.109:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:36Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58029 state=5 |
| 2026-10-24T06:14:36Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58029 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:36Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:58031 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:40Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58041 state=5 |
| 2026-10-24T06:14:40Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:58040 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:40Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58041 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:44Z | admin | lab-pc | network/connect | 140.82.113.22 | tcp 10.4.55.6:58051 -> 140.82.113.22:443 state=5 proc=WorkBuddy.exe |
| 2026-10-24T06:14:46Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58059 state=5 |
| 2026-10-24T06:14:46Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58059 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:50Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58067 state=5 |
| 2026-10-24T06:14:50Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58067 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:56Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:56630 -> 127.0.0.1:58080 state=5 |
| 2026-10-24T06:14:56Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:58080 -> 127.0.0.1:56630 state=5 |
| 2026-10-24T06:14:58Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:7897 -> 127.0.0.1:57445 state=5 |
| 2026-10-24T06:14:58Z | admin | lab-pc | network/connect | 127.0.0.1 | tcp 127.0.0.1:57445 -> 127.0.0.1:7897 state=5 proc=msedgewebview2.exe |
| 2026-10-24T06:14:58Z | admin | lab-pc | network/connect | 223.6.6.6 | tcp 10.4.55.6:57448 -> 223.6.6.6:443 state=5 |
| 2026-10-24T06:14:58Z | admin | lab-pc | network/connect | 223.5.5.5 | tcp 10.4.55.6:57449 -> 223.5.5.5:443 state=5 |
| 2026-10-24T06:14:58Z | admin | lab-pc | network/connect | 120.233.50.192 | tcp 10.4.55.6:58090 -> 120.233.50.192:443 state=5 proc=WorkBuddy.exe |

