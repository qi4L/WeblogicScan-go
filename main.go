package main

import (
	"flag"
	"fmt"
	"qi4l/utils"
)

var (
	Url   string
	Port  string
	EXP   string
	Cmd   string
	Ldap  string
	Rip   string
	Rport string
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
  `)
}

func main() {
	flag.StringVar(&Url, "u", "", "your target")
	flag.StringVar(&Port, "p", "", "you target Port")
	flag.StringVar(&EXP, "e", "", "only detect")
	flag.StringVar(&Cmd, "c", "calc.exe", "command")
	flag.StringVar(&Ldap, "l", "", "ldap server")
	flag.StringVar(&Rip, "ri", "", "reverse ip")
	flag.StringVar(&Rport, "rp", "", "reverse port")
	flag.Usage = usage
	flag.Parse()

	//if Url == "" || Port == "" {
	//	usage()
	//	os.Exit(0)
	//}

	qi4l := utils.WorkExp{
		Url:   Url,
		Port:  Port,
		EXP:   EXP,
		Cmd:   Cmd,
		Ldap:  Ldap,
		Rip:   Rip,
		Rport: Rport,
	}
	qi4l.WeblogicScanRun()
}
