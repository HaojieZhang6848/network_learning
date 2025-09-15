// cmd/mini-overlay/main.go
package main

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/songgao/water"
	"golang.org/x/crypto/nacl/secretbox"
	"k8s.io/klog/v2"
)

const (
	// 尽量避免外层碎片：1300 作为内层 MTU（留出 UDP+IP+加密开销）
	innerMTU = 1300
)

type box struct {
	key    [32]byte
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
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	var (
		ifCIDR = flag.String("cidr", "192.168.124.1/24", "virtual interface CIDR (e.g. 192.168.124.1/24)")
		local  = flag.String("local", ":51820", "local UDP addr (host:port)")
		peer   = flag.String("peer", "", "peer UDP addr (host:port)")
		pskB64 = flag.String("psk", "", "base64 32-byte pre-shared key (optional)")
		ifName = flag.String("ifname", "", "TUN name (optional)")
	)
	flag.Parse()
	klog.Info("mini-overlay starting...")

	// 初始化 TUN
	cfg := water.Config{DeviceType: water.TUN}
	if *ifName != "" {
		cfg.Name = *ifName
	}
	ifce, err := water.New(cfg)
	must(err)
	klog.Info("TUN:", ifce.Name())

	// 自动配置 TUN IP/MTU
	klog.Infof("Configuring TUN interface %s with %s and MTU %d...", ifce.Name(), *ifCIDR, innerMTU)

	// 添加 IP 地址
	cmd1 := exec.Command("ip", "addr", "add", *ifCIDR, "dev", ifce.Name())
	if err := cmd1.Run(); err != nil {
		log.Printf("Failed to add IP address: %v", err)
		klog.Infof("Please run manually: sudo ip addr add %s dev %s", *ifCIDR, ifce.Name())
	} else {
		klog.Infof("IP address %s added to %s", *ifCIDR, ifce.Name())
	}

	// 设置接口状态为 up 并配置 MTU
	cmd2 := exec.Command("ip", "link", "set", "dev", ifce.Name(), "up", "mtu", fmt.Sprintf("%d", innerMTU))
	if err := cmd2.Run(); err != nil {
		log.Printf("Failed to bring interface up: %v", err)
		klog.Infof("Please run manually: sudo ip link set dev %s up mtu %d", ifce.Name(), innerMTU)
	} else {
		klog.Infof("Interface %s is up with MTU %d", ifce.Name(), innerMTU)
	}

	klog.Info("")

	// 准备 UDP
	laddr, err := net.ResolveUDPAddr("udp", *local)
	must(err)
	conn, err := net.ListenUDP("udp", laddr)
	must(err)
	defer conn.Close()
	klog.Info("UDP listen on", conn.LocalAddr())

	var raddr *net.UDPAddr
	if *peer != "" {
		raddr, err = net.ResolveUDPAddr("udp", *peer)
		must(err)
		klog.Info("Peer:", raddr.String())
	}

	// 预共享密钥（可选）
	var b box
	if *pskB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(*pskB64)
		must(err)
		if len(raw) != 32 {
			log.Fatalf("psk length must be 32, got %d", len(raw))
		}
		copy(b.key[:], raw)
		b.enable = true
		klog.Info("Encryption: secretbox enabled")
	} else {
		klog.Info("Encryption: disabled (PSK not provided)")
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
			out = out[:0]
			sealed, err := b.seal(out, pkt)
			if err != nil {
				log.Println("seal:", err)
				continue
			}
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
				klog.Info("Peer learned:", raddr.String())
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

	<-stop
	klog.Info("Bye.")
}
