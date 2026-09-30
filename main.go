// xgate — 单二进制,跑在受限沙箱 X 上。解决「只能出站、无法被 SSH 回来」。
//
// 架构(已按真实环境修正):
//
//	X  --(cloudflared access ssh)-->  oracle_4:22        ← 唯一的出站,SSH 裹在 TLS 里
//	oracle_4 上挂 127.0.0.1:2222                          ← 不需要 GatewayPorts
//	你 --ProxyJump--> oracle_4 --> 127.0.0.1:2222
//	    ↑ oracle_4 的 sshd 通过【已存在的连接】开 forwarded-tcpip 回到 X
//	    ↑ X 侧 xgate 不做任何 socket 连接,直接在进程内这条 net.Conn 上跑内嵌 sshd
//
// X 的网卡上从头到尾只有一条到 Cloudflare 的 TLS。SSH 协议只活在
// TLS 密文 + 进程内存中,不 listen()、不绑任何 socket、不碰 loopback,
// 因此 X 上的 netfilter/DPI 无从 reset。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	targetHost  = flag.String("target-host", "", "反向:目标主机(Cloudflare Access 应用域名,必填)")
	oracleUser  = flag.String("user", "", "连目标主机的 SSH 用户名(必填)")
	identity    = flag.String("identity", defaultIdPath(), "连目标主机用的私钥")
	reversePort = flag.Int("reverse-port", 2222, "在目标主机上挂的反向端口")
	reverseBind = flag.String("reverse-bind", "127.0.0.1", "反向端口绑定地址(默认仅本机,免 GatewayPorts)")
	hostKeyPath = flag.String("host-key", defaultXgatePath("host_key"), "内嵌 sshd host key")
	akPath      = flag.String("authorized-keys", defaultXgatePath("authorized_keys"), "内嵌 sshd 授权公钥")
	cfBin       = flag.String("cloudflared", "cloudflared", "cloudflared 可执行文件路径")
	keepalive   = flag.Duration("keepalive", 30*time.Second, "出站 SSH 保活间隔")
	verbose     = flag.Bool("v", false, "打印 cloudflared 原始输出")
)

func defaultIdPath() string {
	if h := os.Getenv("HOME"); h != "" {
		return h + "/.ssh/id_ed25519"
	}
	return ""
}

func defaultXgatePath(name string) string {
	if h := os.Getenv("HOME"); h != "" {
		return h + "/.xgate/" + name
	}
	return name
}

// ---------- 传输层:cloudflared access ssh 的 stdio → net.Conn ----------

// pipeConn 把子进程的 stdin/stdout 包装成 net.Conn,让 SSH 客户端
// 直接跑在 cloudflared 隧道上。这正是 ProxyCommand 的等价物,
// 但由 xgate 内部自己持有,不需要外部 ssh 客户端。
type pipeConn struct {
	r      io.ReadCloser
	w      io.WriteCloser
	cmd    *exec.Cmd
	closed chan struct{}
	once   sync.Once
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.w.Write(b) }

func (p *pipeConn) Close() error {
	p.once.Do(func() {
		close(p.closed)
		p.r.Close()
		p.w.Close()
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
	})
	return nil
}

// stdio 管道无法安全实现 deadline;外层重连循环负责兜底。
func (p *pipeConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (p *pipeConn) RemoteAddr() net.Addr               { return pipeAddr{} }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "cloudflared" }

// dialCloudflared 启动 `cloudflared access ssh --hostname <h>`,
// 返回的 conn 上跑的字节流就是目标主机 22 端口的 SSH 协议。
func dialCloudflared(host string) (net.Conn, error) {
	cmd := exec.Command(*cfBin, "access", "ssh", "--hostname", host)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if *verbose {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 %s 失败: %w", *cfBin, err)
	}
	return &pipeConn{r: stdout, w: stdin, cmd: cmd, closed: make(chan struct{})}, nil
}

// ---------- 内嵌 sshd 基础设施 ----------

func ensureHostKey(path string) ssh.Signer {
	if data, err := os.ReadFile(path); err == nil {
		if s, err := ssh.ParsePrivateKey(data); err == nil {
			return s
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		log.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("已生成内嵌 sshd host key: %s", path)
	return s
}

func loadAuthorizedKeys(path string) map[string]bool {
	m := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("读取 authorized_keys 失败(%s): %v", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		m[string(pk.Marshal())] = true
	}
	if len(m) == 0 {
		log.Fatalf("authorized_keys 为空或无可解析公钥: %s", path)
	}
	return m
}

func buildServerConfig(hostKey ssh.Signer, ak map[string]bool) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if ak[string(key.Marshal())] {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	cfg.AddHostKey(hostKey)
	return cfg
}

// ---------- 进程内 sshd(核心,不碰任何 socket) ----------

// serveEmbeddedSSH 在进程内信道上跑 SSH 服务端。
// conn 来自 forwarded-tcpip,不是 socket,netfilter/DPI 看不见。
func serveEmbeddedSSH(conn net.Conn, serverCfg *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		go handleSession(ch)
	}
}

func handleSession(newCh ssh.NewChannel) {
	if newCh.ChannelType() != "session" {
		newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	s := &session{ch: ch}

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_, cols, rows, _, _ := parsePtyReq(req.Payload)
			s.winsize = &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}
			req.Reply(true, nil)
		case "window-change":
			cols, rows, _, _ := parseWinChg(req.Payload)
			s.mu.Lock()
			if s.pty != nil {
				_ = pty.Setsize(s.pty, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
			}
			s.mu.Unlock()
			req.Reply(true, nil)
		case "env":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			s.startShell()
			return
		case "exec":
			req.Reply(true, nil)
			s.startExec(string(req.Payload[4:])) // 跳过 uint32 长度前缀
			return
		case "subsystem":
			if string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				s.startSftp()
				return
			}
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
	ch.Close()
}

type session struct {
	ch      ssh.Channel
	pty     *os.File
	mu      sync.Mutex
	winsize *pty.Winsize
}

func (s *session) startShell() {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	cmd := exec.Command(shell)
	if s.winsize != nil {
		f, err := pty.StartWithSize(cmd, s.winsize)
		if err != nil {
			s.ch.Close()
			return
		}
		s.mu.Lock()
		s.pty = f
		s.mu.Unlock()
		go func() {
			io.Copy(f, s.ch)
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}()
		io.Copy(s.ch, f)
		_ = cmd.Wait()
		s.ch.Close()
		return
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.ch, s.ch, s.ch
	_ = cmd.Run()
	s.ch.Close()
}

// startExec: scp(老式)走这里,命令形如 "scp -t /path"。
func (s *session) startExec(cmdline string) {
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.ch, s.ch, s.ch
	_ = cmd.Run()
	s.ch.Close()
}

// startSftp: sftp 子系统 / 新式 scp(用 sftp 后端)走这里。
func (s *session) startSftp() {
	server, err := sftp.NewServer(s.ch)
	if err != nil {
		s.ch.Close()
		return
	}
	defer server.Close()
	_ = server.Serve()
	s.ch.Close()
}

// ---------- SSH 协议负载解析 ----------

func parseString(b []byte) (string, []byte) {
	l := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	return string(b[:l]), b[l:]
}

func parsePtyReq(p []byte) (term string, cols, rows, wpix, hpix uint32) {
	term, p = parseString(p)
	cols = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	rows = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	wpix = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	hpix = binary.BigEndian.Uint32(p[:4])
	return
}

func parseWinChg(p []byte) (cols, rows, wpix, hpix uint32) {
	cols = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	rows = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	wpix = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	hpix = binary.BigEndian.Uint32(p[:4])
	return
}

// ---------- 反向隧道 ----------

func loadIdentity(path string) ssh.Signer {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("读取身份私钥失败(%s): %v", path, err)
	}
	s, err := ssh.ParsePrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			log.Fatalf("私钥 %s 有 passphrase,xgate 不支持交互输入", path)
		}
		log.Fatalf("私钥解析失败: %v", err)
	}
	return s
}

func connectReverse(signer ssh.Signer) (*ssh.Client, net.Listener, error) {
	conn, err := dialCloudflared(*targetHost)
	if err != nil {
		return nil, nil, err
	}
	clientCfg := &ssh.ClientConfig{
		User:            *oracleUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 受控环境;硬化可换 known_hosts
		Timeout:         30 * time.Second,
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, *targetHost+":22", clientCfg)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	client := ssh.NewClient(ncc, chans, reqs)
	go ssh.DiscardRequests(reqs)

	addr := *reverseBind + ":" + strconv.Itoa(*reversePort)
	l, err := client.Listen("tcp", addr)
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	// 保活:出站这条连接是唯一生命线,断了就彻底失联。
	if *keepalive > 0 {
		go func() {
			t := time.NewTicker(*keepalive)
			defer t.Stop()
			for range t.C {
				if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					return
				}
			}
		}()
	}
	return client, l, nil
}

func runReverse() {
	signer := loadIdentity(*identity)
	_ = os.MkdirAll(filepath.Dir(*hostKeyPath), 0700)
	serverCfg := buildServerConfig(ensureHostKey(*hostKeyPath), loadAuthorizedKeys(*akPath))

	for {
		client, l, err := connectReverse(signer)
		if err != nil {
			log.Printf("反向连接失败: %v —— 5s 后重试", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("反向隧道已建立:%s 上监听 %s (经 cloudflared,不依赖 GatewayPorts)",
			*targetHost, *reverseBind+":"+strconv.Itoa(*reversePort))
		for {
			c, err := l.Accept()
			if err != nil {
				log.Printf("监听断开(%v),重连中", err)
				client.Close()
				break
			}
			go serveEmbeddedSSH(c, serverCfg)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: xgate reverse --target-host <cf-access-host> --user <u> [flags]")
		os.Exit(2)
	}
	if os.Args[1] != "reverse" {
		log.Fatalf("未知子命令: %s(当前仅支持 reverse)", os.Args[1])
	}
	flag.CommandLine.Parse(os.Args[2:])
	if *targetHost == "" || *oracleUser == "" {
		log.Fatal("reverse 模式必须指定 --target-host 和 --user")
	}
	runReverse()
}
