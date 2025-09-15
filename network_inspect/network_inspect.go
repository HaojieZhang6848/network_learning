package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const sysClassNet = "/sys/class/net"

type IfInfo struct {
	Name       string
	Type       string
	MTU        int
	Flags      string
	MAC        string
	IPs        []string
	OperState  string
	Carrier    string
	Speed      string
	Duplex     string
	Driver     string
	SysfsPath  string
	Master     string // 上级设备（如 bridge/bond）
	IsVirtual  bool
}

func main() {
	ifaces, err := os.ReadDir(sysClassNet)
	if err != nil {
		fmt.Println("read sysfs:", err)
		return
	}

	var list []IfInfo
	for _, de := range ifaces {
		name := de.Name()
		info, err := inspectIface(name)
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
			continue
		}
		list = append(list, info)
	}

	// 输出
	for _, it := range list {
		fmt.Printf("=== %s ===\n", it.Name)
		fmt.Printf("Type:       %s\n", it.Type)
		fmt.Printf("State:      %s  Carrier:%s  MTU:%d  Flags:%s\n", it.OperState, it.Carrier, it.MTU, it.Flags)
		fmt.Printf("MAC:        %s\n", it.MAC)
		if len(it.IPs) > 0 {
			fmt.Printf("IPs:        %s\n", strings.Join(it.IPs, ", "))
		} else {
			fmt.Printf("IPs:        (none)\n")
		}
		if it.Speed != "" || it.Duplex != "" {
			fmt.Printf("Speed/Duplex: %s / %s\n", dash(it.Speed), dash(it.Duplex))
		}
		fmt.Printf("Driver:     %s\n", dash(it.Driver))
		if it.Master != "" {
			fmt.Printf("Master:     %s\n", it.Master)
		}
		fmt.Printf("Sysfs:      %s\n", it.SysfsPath)
		fmt.Println()
	}
}

func inspectIface(name string) (IfInfo, error) {
	var out IfInfo
	out.Name = name

	syslink := filepath.Join(sysClassNet, name)
	real, _ := filepath.EvalSymlinks(syslink)
	out.SysfsPath = real

	out.IsVirtual = strings.Contains(real, "/virtual/")

	ifi, err := net.InterfaceByName(name)
	if err == nil {
		out.MTU = ifi.MTU
		out.Flags = ifi.Flags.String()
		out.MAC = ifi.HardwareAddr.String()
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			out.IPs = append(out.IPs, a.String())
		}
	}

	out.OperState = readFirst(filepath.Join(syslink, "operstate"))
	out.Carrier = readFirst(filepath.Join(syslink, "carrier"))
	out.Speed = readFirst(filepath.Join(syslink, "speed"))   // Mb/s（部分虚拟口没有）
	out.Duplex = readFirst(filepath.Join(syslink, "duplex")) // full/half（部分虚拟口没有）

	out.Driver = detectDriver(syslink)
	out.Master = detectMaster(syslink)

	// 判别类型（按特征由强到弱）
	out.Type = classify(name, syslink, real, out)

	return out, nil
}

func classify(name, syslink, real string, info IfInfo) string {
	// 1) 明确特征目录
	if exists(filepath.Join(syslink, "bridge")) {
		return "bridge"
	}
	if exists(filepath.Join(syslink, "bonding")) {
		return "bond"
	}
	if exists(filepath.Join(syslink, "team")) {
		return "team"
	}
	if exists(filepath.Join(syslink, "vxlan")) {
		return "vxlan"
	}
	// vlan: /proc/net/vlan/<iface> 存在即为 VLAN 子接口
	if exists(filepath.Join("/proc/net/vlan", name)) {
		return "vlan"
	}
	// tun/tap: 有 tun_flags；用位判断
	if exists(filepath.Join(syslink, "tun_flags")) {
		flagsStr := readFirst(filepath.Join(syslink, "tun_flags"))
		if v, err := strconv.ParseUint(strings.TrimSpace(flagsStr), 0, 32); err == nil {
			const IFF_TUN = 0x0001
			const IFF_TAP = 0x0002
			if v&IFF_TAP != 0 {
				return "tap (TAP virtual L2)"
			}
			if v&IFF_TUN != 0 {
				return "tun (TUN virtual L3)"
			}
			return "tun/tap"
		}
		return "tun/tap"
	}

	// 2) 驱动名直判
	switch info.Driver {
	case "veth":
		return "veth (virtual ethernet pair)"
	case "wireguard":
		return "wireguard (VPN)"
	case "macvlan":
		return "macvlan"
	case "ipvlan":
		return "ipvlan"
	case "dummy":
		return "dummy"
	case "tun":
		// 某些内核/发行版 tun/tap 的 driver 都显示为 "tun"
		return "tun/tap"
	case "bridge":
		return "bridge"
	case "team":
		return "team"
	}

	// 3) 名字启发式（备选）
	if name == "lo" || strings.Contains(info.Flags, "loopback") {
		return "loopback"
	}
	if strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "br") {
		return "bridge"
	}
	if strings.HasPrefix(name, "veth") {
		return "veth (virtual ethernet pair)"
	}
	if strings.HasPrefix(name, "gre") || strings.HasPrefix(name, "gretap") {
		return "gre/gretap"
	}
	if strings.HasPrefix(name, "vxlan") {
		return "vxlan"
	}
	if strings.HasPrefix(name, "wg") {
		return "wireguard"
	}
	if strings.HasPrefix(name, "bond") {
		return "bond"
	}
	if strings.HasPrefix(name, "team") {
		return "team"
	}
	if strings.HasPrefix(name, "macvlan") {
		return "macvlan"
	}
	if strings.HasPrefix(name, "ipvlan") {
		return "ipvlan"
	}
	if strings.HasPrefix(name, "tap") {
		return "tap"
	}
	if strings.HasPrefix(name, "tun") {
		return "tun"
	}
	if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "cni") {
		return "bridge (container)"
	}
	if strings.HasPrefix(name, "flannel.") {
		return "vxlan (flannel overlay)"
	}

	// 4) 物理 vs 虚拟 的兜底
	if info.IsVirtual {
		if info.Driver != "" {
			return "virtual (" + info.Driver + ")"
		}
		return "virtual"
	}
	if info.Driver != "" {
		return "physical (" + info.Driver + ")"
	}
	return "physical"
}

func detectDriver(syslink string) string {
	drv := filepath.Join(syslink, "device", "driver")
	if target, err := filepath.EvalSymlinks(drv); err == nil && target != "" {
		// 最后一个目录名就是驱动名
		return filepath.Base(target)
	}
	// 某些虚拟设备没有 device/driver，可尝试 module 名
	mod := filepath.Join(syslink, "device", "modalias")
	if b, err := os.ReadFile(mod); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func detectMaster(syslink string) string {
	m := filepath.Join(syslink, "master")
	if target, err := filepath.EvalSymlinks(m); err == nil && target != "" {
		return filepath.Base(target)
	}
	return ""
}

func readFirst(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
