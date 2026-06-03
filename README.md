# 森岳 2FA

一个可用 Docker Compose 部署的网页端 TOTP 2FA 验证器。

## 特性

- 浏览器本地生成 6 位 TOTP 验证码
- Secret 不上传到服务器
- 使用主密码通过 PBKDF2 + AES-GCM 加密后保存在 localStorage
- Docker Compose 使用 nginx 提供静态页面

## 部署

```powershell
cd D:\森岳2FA
docker compose up -d
```

访问：

```text
http://localhost:8070
```

如需修改端口，编辑 `docker-compose.yml`：

```yaml
ports:
  - "8070:80"
```

把左侧 `8070` 改成你想暴露的端口即可。

## 重要说明

- 首次输入的主密码用于创建本地加密保险库。
- 忘记主密码后无法恢复已保存的 Secret。
- 更换浏览器、清理站点数据或 localStorage 会导致本地保存的账号消失。
- 建议只在可信网络中使用，并为站点配置 HTTPS 后再远程访问。

