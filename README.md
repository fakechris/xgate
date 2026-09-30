# xgate

跑在**只能出站**的受限机器（sandbox）上的反向 SSH 入口。让你从外网能 SSH 回这台机器——即使它不装 sshd、不能 `listen()`、且本机出站流量被 netfilter / DPI 拦截。

## 原理

普通 `ssh -R` 反向隧道在 X 这一侧，server 端 sshd 必须**连回 `127.0.0.1:22`** 才能把流量递回来。这一步让 SSH 协议明文跑在 X 的 loopback 上，被 DPI 一刀 reset——所以「只能出站、回不来」。

xgate 跳过了这一步：

- X **主动**通过 `cloudflared access ssh` 出站，SSH 协议裹在 TLS 里，DPI 放行
- 在中转主机上挂一个反向端口
- 外来连接经 `forwarded-tcpip` 通道**顺着已有连接的内存管道**回到 X
- xgate **不 `net.Dial`、不 `net.Listen`**，直接在这条内存 `net.Conn` 上跑内嵌 SSH 服务端

于是 SSH 协议只存在于两个地方：TLS 密文里（出站）和 xgate 进程堆内存里（抓不到包）。netfilter/DPI 无从 reset。

```
[你] ──ssh -J──▶ [中转主机 :2222] ═══TLS═══▶ [X: xgate 进程内 sshd]
                     │                        (不碰任何 socket)
                     └── 反向端口(127.0.0.1) ──┘
```

## 特性

- **零依赖单二进制**，`CGO_ENABLED=0` 静态编译
- X 上不需要 sshd、不需要 root、不开任何监听端口
- 只认公钥（`authorized_keys`），无密码入口
- 支持交互 shell、PTY、`scp`（老式 exec 与 sftp 后端）、`sftp`
- 出站连接自动保活 + 断线 5s 自动重连
- 反向端口默认只绑 `127.0.0.1`，无需改目标机 sshd 的 `GatewayPorts`

## 使用

### 1. 在受限机器 X 上下载运行

```bash
ARCH=$(uname -m)   # x86_64 -> amd64, aarch64 -> arm64
curl -fsSL -o xgate \
  "https://github.com/fakechris/xgate/releases/latest/download/xgate_linux_${ARCH}"
chmod +x xgate
```

### 2. 放你的公钥

```bash
mkdir -p ~/.xgate
cat ~/.ssh/id_ed25519.pub > ~/.xgate/authorized_keys
```

### 3. 启动反向隧道

```bash
./xgate reverse \
  --target-host <Cloudflare Access 应用域名> \
  --user <该主机的 ssh 用户> \
  --identity ~/.ssh/<连出去用的私钥> \
  --reverse-port 2222
```

`--cloudflared` 可指定 cloudflared 路径。

**不需要 root，也不需要 sudo。** xgate 完全以当前用户身份运行。

如果 `cloudflared` 就在当前目录（`./cloudflared`），xgate 会**自动找到它**，无需任何额外参数——探测顺序为：

1. 显式 `--cloudflared <路径>`
2. `./cloudflared`（及 `./cloudflared-linux-{amd64,arm64}`）
3. `PATH`
4. `/usr/local/bin`、`/usr/bin`、`/snap/bin`

只有在全都找不到时才会报错，并列出已查找的位置。

### 4. 从你的机器连回去

```bash
ssh -J <user>@<target-host> -p 2222 <x上的用户名>@127.0.0.1
```

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--target-host` | 必填 | Cloudflare Access 应用域名 |
| `--user` | 必填 | 连该主机的 SSH 用户名 |
| `--identity` | `~/.ssh/id_ed25519` | 出站用私钥 |
| `--reverse-port` | `2222` | 目标主机上挂的反向端口 |
| `--reverse-bind` | `127.0.0.1` | 反向端口绑定地址（仅本机，免 GatewayPorts） |
| `--host-key` | `~/.xgate/host_key` | 内嵌 sshd host key |
| `--authorized-keys` | `~/.xgate/authorized_keys` | 授权公钥 |
| `--cloudflared` | 自动探测 | cloudflared 路径（留空则依次查找 `./`、PATH、常见安装位置） |
| `--keepalive` | `30s` | 出站保活间隔 |
| `-v` | `false` | 打印 cloudflared 原始输出 |

## 安全须知

- **别用 root 跑**——内嵌 sshd 的 shell 权限 = 运行 xgate 那个用户的权限
- 内嵌 sshd 对目标主机的连接使用 `InsecureIgnoreHostKey()`；严格环境请换成 known_hosts 校验
- 出站隧道是唯一入口，断了就失联——生产请用 systemd `--user` 或 supervisor 守护
- `--identity` 私钥**不能带 passphrase**（xgate 不做交互输入）

## 局限性

- 无 root 提权
- PTY 之外的环境变量传递做了简化
- 需要在 X 上预先手动启动 xgate（无自动保活兜底进程）

## License

MIT
