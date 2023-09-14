package main

import (
	"WeblogicScan/utils"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	Url    string
	Port   string
	EXP    string
	Cmd    string
	Ldap   string
	Rip    string
	Rport  string
	Thread int
	file   string
)

func usage() {
	fmt.Println(`Usage of main.exe:
  -u url
      you target, example: 127.0.0.1
  -p Port
      you target Port, example: "whoami"
  -e EXP
      Exploitation alone, example: ""
  -l ldap
      ldap server, example: "ldap://127.0.0.1/#eval"
  -ri rip
	  reverse ip
  -rp rport
	  reverse port
  -f targets.txt
	  Read the target from the file and test the vulnerabilities in batches

  `)
}

// 使用函数来解析每行并提取主机和端口信息
func parseHostAndPort(line string) (host, port string) {
	parts := strings.Split(line, ":")
	host = parts[0]
	if len(parts) > 1 {
		port = parts[1]
	} else {
		port = "7001" // 设置默认端口为7001
	}
	return host, port
}

func main() {
	flag.StringVar(&Url, "u", "", "your target")
	flag.StringVar(&file, "f", "", "Specify batch target")
	flag.StringVar(&Port, "p", "", "your target Port")
	flag.StringVar(&EXP, "e", "", "only detect")
	flag.StringVar(&Cmd, "c", "calc.exe", "command")
	flag.StringVar(&Ldap, "l", "", "ldap server")
	flag.StringVar(&Rip, "ri", "", "reverse ip")
	flag.StringVar(&Rport, "rp", "", "reverse port")
	flag.Usage = usage
	flag.Parse()

	if Port != "" && file != "" {
		usage()
		os.Exit(0)
	}

	qi4l := utils.WorkExp{
		Url:   Url,
		Port:  Port,
		EXP:   EXP,
		Cmd:   Cmd,
		Ldap:  Ldap,
		Rip:   Rip,
		Rport: Rport,
	}

	lines, err := utils.ReadLinesFromFile(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	/*原版代码
	for _, line := range lines {
		fmt.Println("扫描 " + line + "的结果:")
		parts := strings.Split(line, ":")
		qi4l.Url = parts[0]
		qi4l.Port = parts[1]
		qi4l.WeblogicScanRun()
	}*/

	for _, line := range lines {
		host, port := parseHostAndPort(line) //调用函数进行解析
		fmt.Printf("扫描 %s:%s 的结果:\n", host, port)
		qi4l.Url = host
		qi4l.Port = port
		qi4l.WeblogicScanRun()
	}
	qi4l.WeblogicScanRun()
}
