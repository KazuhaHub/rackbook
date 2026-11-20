package oauthserver

import (
	"errors"
	"fmt"
	"html"
	"net/http"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/locale"
)

// pageReason is why an authorization request was refused on a page (not sent
// back to the client).
type pageReason int

const (
	reasonNotPerson pageReason = iota
	reasonNoClientID
	reasonClient
	reasonRedirect
)

// pageTexts is the wording of the error page in one language. client* name
// the refused client; the lookup's own error follows clientDetail, in English
// (it is technical: what the metadata document got wrong).
type pageTexts struct {
	title, nothing                                string
	notPerson, noClientID, redirect               string
	clientUnknown, clientNotAllowed, clientDetail string
	detailClose                                   string
}

var pageLangs = map[string]pageTexts{
	"en-US": {
		title:            "Authorization failed",
		nothing:          "Nothing was authorized. You can close this page.",
		notPerson:        "Sign in to the console as a person to authorize a client. API tokens and access tokens cannot do this.",
		noClientID:       "The request has no client_id.",
		redirect:         "The redirect_uri is not one the client has registered.",
		clientUnknown:    "This client is not registered with this Rackbook.",
		clientNotAllowed: "This client is not on the allowed_clients list of this Rackbook.",
		clientDetail:     "This client cannot be used: ",
		detailClose:      ".",
	},
	"zh-CN": {
		title:            "授权失败",
		nothing:          "没有授予任何权限。可以关闭此页面。",
		notPerson:        "请先以个人身份登录控制台，再授权客户端。API 令牌和访问令牌不能用来授权。",
		noClientID:       "请求中缺少 client_id。",
		redirect:         "redirect_uri 不是该客户端注册过的地址。",
		clientUnknown:    "该客户端没有在此 Rackbook 注册。",
		clientNotAllowed: "该客户端不在此 Rackbook 的 allowed_clients 列表中。",
		clientDetail:     "无法使用该客户端：",
		detailClose:      "。",
	},
	"zh-TW": {
		title:            "授權失敗",
		nothing:          "沒有授予任何權限。可以關閉此頁面。",
		notPerson:        "請先以個人身分登入主控台，再授權用戶端。API 權杖和存取權杖不能用來授權。",
		noClientID:       "請求中缺少 client_id。",
		redirect:         "redirect_uri 不是該用戶端註冊過的位址。",
		clientUnknown:    "該用戶端沒有在此 Rackbook 註冊。",
		clientNotAllowed: "該用戶端不在此 Rackbook 的 allowed_clients 清單中。",
		clientDetail:     "無法使用該用戶端：",
		detailClose:      "。",
	},
}

// pageLocale is the language of a page for this request: the signed-in
// person's saved preference, else the browser's Accept-Language, else the
// ledger's default language.
func (s *Server) pageLocale(r *http.Request) string {
	def := locale.Default
	if s.o.Config != nil {
		if c := s.o.Config(); c != nil {
			def = c.DefaultLocale()
		}
	}
	if id := auth.FromContext(r.Context()); id != nil && id.ID != "" && s.o.Prefs != nil {
		switch id.Method {
		case auth.MethodToken, auth.MethodOAuth, auth.MethodMCPHub:
		default:
			if l := s.o.Prefs.Locale(id.ID); l != "" {
				return l
			}
		}
	}
	return locale.Match(r.Header.Get("Accept-Language"), def)
}

// errorPage answers an authorization request that cannot be sent back to the
// client (unknown client, redirect_uri that does not match): the person sees
// the problem in their language and nothing is redirected. err is the client
// lookup's error for reasonClient.
func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, why pageReason, err error) {
	lang := s.pageLocale(r)
	t, ok := pageLangs[lang]
	if !ok {
		lang, t = "en-US", pageLangs["en-US"]
	}
	var msg string
	switch why {
	case reasonNotPerson:
		msg = t.notPerson
	case reasonNoClientID:
		msg = t.noClientID
	case reasonRedirect:
		msg = t.redirect
	case reasonClient:
		switch {
		case errors.Is(err, errUnknownClient):
			msg = t.clientUnknown
		case errors.Is(err, errClientNotAllowed):
			msg = t.clientNotAllowed
		case err != nil:
			msg = t.clientDetail + err.Error() + t.detailClose
		default:
			msg = t.clientDetail
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Accept-Language, Cookie")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#222}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}</style></head>
<body><h1>%s</h1><p>%s</p><p>%s</p></body></html>`,
		html.EscapeString(lang), html.EscapeString(t.title), html.EscapeString(t.title), html.EscapeString(msg), html.EscapeString(t.nothing))
}
