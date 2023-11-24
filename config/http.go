package config

import (
	"fmt"
	"github.com/imroc/req/v3"
	"time"
)

type ErrorMessage struct {
	Message string `json:"message"`
}

func (msg *ErrorMessage) Error() string {
	return fmt.Sprintf("API Error: %s", msg.Message)
}

var Client = req.C().
	SetUserAgent("my-custom-client").
	SetTimeout(5 * time.Second).
	EnableDumpEachRequest().
	SetCommonErrorResult(&ErrorMessage{}).
	OnAfterResponse(func(client *req.Client, resp *req.Response) error {
		if resp.Err != nil {
			return nil
		}
		if errMsg, ok := resp.ErrorResult().(*ErrorMessage); ok {
			resp.Err = errMsg
			return nil
		}
		if !resp.IsSuccessState() {
			resp.Err = fmt.Errorf("bad status: %s\nraw content:\n%s", resp.Status, resp.Dump())
		}
		return nil
	})

type WorkExp1 struct {
	Url  string
	Port string
	EXP  string
	Cmd  string
	Ldap string
}
