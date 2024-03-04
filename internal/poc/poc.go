package poc

import (
	"breach/internal/poc/thinkphp"
	"breach/internal/util"
	"slices"
)

type BasePayload interface {
	CheckVul() *util.Response
	ExecVul(cmd string) *util.Response
	GetShell() *util.Response
}
type Poc struct {
	BaseUrl  string
	PocTypes []string
	Payloads []BasePayload
}

func NewPoc(baseUrl string, pocTypes []string) (*Poc, error) {
	poc := &Poc{
		BaseUrl:  baseUrl,
		PocTypes: pocTypes,
		Payloads: []BasePayload{},
	}
	if slices.Contains(pocTypes, "ALL") {
		poc.Payloads = append(poc.Payloads,
			thinkphp.NewTP3Module(baseUrl),
			thinkphp.NewTP3LogModule(baseUrl),
			thinkphp.NewTP3LogRceModule(baseUrl))
		return poc, nil
	}
	if slices.Contains(pocTypes, "Thinkphp") {
		poc.Payloads = append(poc.Payloads,
			thinkphp.NewTP3Module(baseUrl),
			thinkphp.NewTP3LogModule(baseUrl),
			thinkphp.NewTP3LogRceModule(baseUrl))
	}
	return poc, nil
}
