package cve_2020_2551

import (
	"encoding/hex"
	"github.com/gookit/color"
	"net"
	"regexp"
	"time"
)

var (
	VUL     = "CVE-2020-2551"
	VER_SIG = []string{"GIOP"}
)

func doOne(conn net.Conn) []byte {
	hex_data, _ := hex.DecodeString("47494f50010200030000001700000002000000000000000b4e616d6553657276696365")
	_, err := conn.Write(hex_data)
	if err != nil {
		color.Red.Printf("[-] Target weblogic not detected cve-2020-2551\n")
	}
	time.Sleep(1 * time.Second)
	buf := make([]byte, 1024)
	conn.Read(buf)
	var res []byte
	buf1 := make([]byte, 4096)
	count := 0
	for count < 5 {
		n, err1 := conn.Read(buf1)
		if err1 != nil {
			break
		}
		res = append(res, buf1[:n]...)
		time.Sleep(100 * time.Millisecond)
		count += 1
	}
	return res
}

func checkVul(res []byte, index int) {
	p, _ := regexp.Match(VER_SIG[index], res)

	if p {
		color.Green.Printf("[+] The target weblogic has a JAVA deserialization vulnerability: %s\n", VUL)
	} else {
		color.Red.Printf("[-] Target weblogic not detected %s\n", VUL)
	}
}

func Run(rip string, rport string) {
	index := 0
	server_addr := rip + ":" + rport

	conn, err := net.DialTimeout("tcp4", server_addr, 10*time.Second)
	if err != nil {
		color.Red.Printf("[-] Target weblogic not detected cve-2020-2551\n")
		return
	}
	defer conn.Close()
	res := doOne(conn)
	checkVul(res, index)
}
