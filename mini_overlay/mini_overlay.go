// cmd/mini-overlay/main.go
package main

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/songgao/water"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// 尽量避免外层碎片：1300 作为内层 MTU（留出 UDP+IP+加密开销）
	innerMTU = 1300
)

type box struct {
	key   [32]byte
	enable bool
}

func (b *box) seal(dst, msg []byte) ([]byte, error) {
	if !b.enable {
		return append(dst, msg...), nil
	}
	var nonce [24]byte
	if _, err := io.ReadFull(cryptoRand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	out := dst[:0]
	out = append(out, nonce[:]...)
	out = secretbox.Seal(out, msg, &nonce, &b.key)
	return out, nil
}

func (b *box) open(dst, pkt []byte) ([]byte, bool) {
	if !b.enable {
		return append(dst, pkt...), true
	}
	if len(pkt) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], pkt[:24])
	out, ok := secretbox.Open(dst[:0], pkt[24:], &nonce, &b.key)
	return out, ok
}

func must(err error) {
	if err != nil { log.Fatal(err) }
}

func main() {
	var (
		ifCIDR   = flag.String("cidr", "192.168.124.1/24", "virtual interface CIDR (e.g. 192.168.124.1/24)")
		local    = flag.String("local", ":51820", "local UDP addr (host:port)")
		peer     = flag.String("peer", "", "peer UDP addr (host:port)")
		pskB64   = flag.String("psk", "", "base64 32-byte pre-shared key (optional)")
		ifName   = flag.String("ifname", "", "TUN name (optional)")
	)
	flag.Parse()
	fmt.Println("mini-overlay starting...")

	// 初始化 TUN
	cfg := water.Config{DeviceType: water.TUN}
	if *ifName != "" { cfg.Name = *ifName }
	ifce, err := water.New(cfg)
	must(err)
	fmt.Println("TUN:", ifce.Name())

	// 配置 TUN IP/MTU（Linux/macOS 常见命令；Windows 需改用 netsh 或 Wintun 工具）
	// Linux:
	//   sudo ip addr add 192.168.124.1/24 dev <ifce>
	//   sudo ip link set dev <ifce> up mtu 1300
	// macOS:
	//   sudo ifconfig <ifce> 192.168.124.1 192.168.124.1 netmask 255.255.255.0 mtu 1300 up
	fmt.Printf("Remember to set IP and MTU, e.g. Linux:\n  sudo ip addr add %s dev %s && sudo ip link set dev %s up mtu %d\n\n",
		*ifCIDR, ifce.Name(), ifce.Name(), innerMTU)

	// 准备 UDP
	laddr, err := net.ResolveUDPAddr("udp", *local)
	must(err)
	conn, err := net.ListenUDP("udp", laddr)
	must(err)
	defer conn.Close()
	fmt.Println("UDP listen on", conn.LocalAddr())

	var raddr *net.UDPAddr
	if *peer != "" {
		raddr, err = net.ResolveUDPAddr("udp", *peer)
		must(err)
		fmt.Println("Peer:", raddr.String())
	}

	// 预共享密钥（可选）
	var b box
	if *pskB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(*pskB64)
		must(err)
		if len(raw) != 32 { log.Fatalf("psk length must be 32, got %d", len(raw)) }
		copy(b.key[:], raw)
		b.enable = true
		fmt.Println("Encryption: secretbox enabled")
	} else {
		fmt.Println("Encryption: disabled (PSK not provided)")
	}

	// ctrl+c 退出
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// 从 TUN -> UDP
	go func() {
		buf := make([]byte, 1<<16)
		out := make([]byte, 0, 1<<16)
		for {
			n, err := ifce.Read(buf)
			if err != nil {
				log.Println("tun read:", err)
				return
			}
			pkt := buf[:n]
			// // 简单丢弃大于内层 MTU 的包（生产建议做分片/PMTU）
			// if len(pkt) > innerMTU {
			// 	continue
			// }
			out = out[:0]
			sealed, err := b.seal(out, pkt)
			if err != nil { log.Println("seal:", err); continue }
			if raddr == nil {
				continue // 没配置对端就不发
			}
			if _, err := conn.WriteToUDP(sealed, raddr); err != nil {
				log.Println("udp write:", err)
			}
		}
	}()

	// 从 UDP -> TUN
	go func() {
		buf := make([]byte, 1<<16)
		out := make([]byte, 1<<16)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Println("udp read:", err)
				return
			}
			// 如果没指定 peer，则首次来包的人即为 peer（简易自发现）
			if raddr == nil {
				raddr = from
				fmt.Println("Peer learned:", raddr.String())
			}
			plain, ok := b.open(out[:0], buf[:n])
			if !ok {
				continue
			}
			if _, err := ifce.Write(plain); err != nil {
				log.Println("tun write:", err)
			}
		}
	}()

	// 简单 keepalive（打洞/维持 NAT 映射）
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			if raddr != nil {
				// 发送零长密文也行；这里发 1 字节随机“探活”
				p := []byte{byte(rand.Intn(256))}
				msg, err := b.seal(nil, p)
				if err == nil {
					_, _ = conn.WriteToUDP(msg, raddr)
				}
			}
		}
	}()

	<-stop
	fmt.Println("Bye.")
}
