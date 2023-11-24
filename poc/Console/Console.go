package Console

import (
	"WeblogicScan/config"
	"github.com/gookit/color"
	"net/http"
)

func islive(u string, port string) int {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := "http://" + u + ":" + port + "/console/login/LoginForm.jsp"
	request, err := http.NewRequest("GET", url, nil)
	request.Header.Set("User-Agent", config.Fakeua())
	if err != nil {
		return -1
	}
	response, err := client.Do(request)
	if err != nil {
		return -1
	}
	defer response.Body.Close()
	//body, err := ioutil.ReadAll(response.Body)
	//fmt.Println("body:", string(body))

	status := response.StatusCode
	return status
}

func Run(u string, port string) {

	if islive(u, port) == 200 {
		url := "http://" + u + ":" + port + "/console/login/LoginForm.jsp"
		color.Green.Printf("[+] The target Weblogic console address is exposed!\n[+] The path is: %s \n[+] Please try weak password blasting!\n", url)
	} else {
		color.Red.Printf("[-] Target Weblogic console address not found!\n")
	}

}
