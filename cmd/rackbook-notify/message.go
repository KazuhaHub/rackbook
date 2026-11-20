package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/kazuhahub/rackbook/modsettings"
	"github.com/kazuhahub/rackbook/modules/rbclient"
)

type Digest struct {
	Subject string
	Body    string
}

// texts is the wording of one language. The language comes from the config
// (the local file or the console's module settings), never from a request.
type texts struct {
	prefix, sep       string // before a subject ("Rackbook: "); between its parts
	expired, expiring string
	subject           func(expired, expiring int) string
	expires           string
	daysLeft          string
	source            string
	manual            string
	link              string
	intro             string
	failedIntro       string
	failedSubject     func(n int) string
	failedRun         string
	// the notice sent when the recipients change; the body takes the old and
	// new recipients and the modules page
	recipientsSubject string
	recipientsBody    string
}

var langs = map[string]texts{
	"en-US": {
		prefix:   "Rackbook: ",
		sep:      ", ",
		expired:  "EXPIRED",
		expiring: "EXPIRING",
		subject: func(a, b int) string {
			var parts []string
			if a > 0 {
				parts = append(parts, fmt.Sprintf("%d expired", a))
			}
			if b > 0 {
				parts = append(parts, fmt.Sprintf("%d expiring", b))
			}
			return strings.Join(parts, ", ")
		},
		expires:     "Expires",
		daysLeft:    "Days left",
		source:      "Source",
		manual:      "manual",
		link:        "Link",
		intro:       "These records crossed a reminder threshold:",
		failedIntro: "These module runs failed:",
		failedSubject: func(n int) string {
			if n == 1 {
				return "1 module run failed"
			}
			return fmt.Sprintf("%d module runs failed", n)
		},
		failedRun:         "failed",
		recipientsSubject: "recipients changed",
		recipientsBody:    "The recipients of the expiry reminders changed.\n\nBefore: %s\nNow: %s\n\nIf you did not expect this, check the Modules page at %s.\n",
	},
	"zh-CN": {
		prefix:   "Rackbook：",
		sep:      "，",
		expired:  "已过期",
		expiring: "即将到期",
		subject: func(a, b int) string {
			var parts []string
			if a > 0 {
				parts = append(parts, fmt.Sprintf("%d 项已过期", a))
			}
			if b > 0 {
				parts = append(parts, fmt.Sprintf("%d 项即将到期", b))
			}
			return strings.Join(parts, "，")
		},
		expires:           "到期日",
		daysLeft:          "剩余天数",
		source:            "来源",
		manual:            "手动",
		link:              "链接",
		intro:             "以下记录已达到提醒阈值：",
		failedIntro:       "以下模块运行失败：",
		failedSubject:     func(n int) string { return fmt.Sprintf("%d 个模块运行失败", n) },
		failedRun:         "失败",
		recipientsSubject: "收件人已变更",
		recipientsBody:    "到期提醒的收件人已变更。\n\n原收件人：%s\n新收件人：%s\n\n如果这不是你预期的改动，请在 %s 的“模块”页面检查。\n",
	},
	"zh-TW": {
		prefix:   "Rackbook：",
		sep:      "，",
		expired:  "已過期",
		expiring: "即將到期",
		subject: func(a, b int) string {
			var parts []string
			if a > 0 {
				parts = append(parts, fmt.Sprintf("%d 筆已過期", a))
			}
			if b > 0 {
				parts = append(parts, fmt.Sprintf("%d 筆即將到期", b))
			}
			return strings.Join(parts, "，")
		},
		expires:           "到期日",
		daysLeft:          "剩餘天數",
		source:            "來源",
		manual:            "手動",
		link:              "連結",
		intro:             "以下紀錄已達到提醒門檻：",
		failedIntro:       "以下模組執行失敗：",
		failedSubject:     func(n int) string { return fmt.Sprintf("%d 個模組執行失敗", n) },
		failedRun:         "失敗",
		recipientsSubject: "收件者已變更",
		recipientsBody:    "到期提醒的收件者已變更。\n\n原收件者：%s\n新收件者：%s\n\n如果這不是你預期的變更，請到 %s 的「模組」頁面檢查。\n",
	},
}

// textsFor is the wording of a language (a tag or an alias); English when it
// is not one rackbook-notify writes in.
func textsFor(lang string) texts {
	if l, ok := modsettings.NotifyLanguage(lang); ok {
		return langs[l]
	}
	return langs["en-US"]
}

func itemLink(base string, it rbclient.Item) string {
	return strings.TrimRight(base, "/") + "/c/" + url.PathEscape(it.Collection) + "/" + url.PathEscape(it.ID)
}

func buildDigest(lang, baseURL string, due []rbclient.Item) Digest {
	return buildDigestWith(lang, baseURL, due, nil)
}

// buildDigestWith is the digest of the reminders that are due plus the module
// runs that failed since the last digest.
func buildDigestWith(lang, baseURL string, due []rbclient.Item, failed []modsettings.ModuleStatus) Digest {
	t := textsFor(lang)
	var expired, expiring int
	var b strings.Builder
	if len(due) > 0 {
		b.WriteString(t.intro + "\n")
	}
	for _, it := range due {
		status := t.expiring
		if it.DaysLeft != nil && *it.DaysLeft < 0 {
			status = t.expired
			expired++
		} else {
			expiring++
		}
		label := it.Label
		if label == "" {
			label = it.ID
		}
		src := it.Source
		if src == "" {
			src = t.manual
		}
		days := 0
		if it.DaysLeft != nil {
			days = *it.DaysLeft
		}
		fmt.Fprintf(&b, "\n[%s] %s / %s\n", status, it.Collection, label)
		fmt.Fprintf(&b, "  %s: %s\n", t.expires, it.Expires)
		fmt.Fprintf(&b, "  %s: %d\n", t.daysLeft, days)
		fmt.Fprintf(&b, "  %s: %s\n", t.source, src)
		fmt.Fprintf(&b, "  %s: %s\n", t.link, itemLink(baseURL, it))
	}
	var parts []string
	if len(due) > 0 {
		parts = append(parts, t.subject(expired, expiring))
	}
	if len(failed) > 0 {
		if len(due) > 0 {
			b.WriteString("\n")
		}
		b.WriteString(t.failedIntro + "\n")
		for _, m := range failed {
			fmt.Fprintf(&b, "\n[%s] %s\n", t.failedRun, m.Name)
			if m.LastRun.Error != "" {
				fmt.Fprintf(&b, "  %s\n", m.LastRun.Error)
			}
			fmt.Fprintf(&b, "  %s\n", m.LastRun.Finished.UTC().Format("2006-01-02 15:04 UTC"))
			fmt.Fprintf(&b, "  %s: %s\n", t.link, strings.TrimRight(baseURL, "/")+"/modules")
		}
		parts = append(parts, t.failedSubject(len(failed)))
	}
	subject := ""
	if len(parts) > 0 {
		subject = t.prefix + strings.Join(parts, t.sep)
	}
	return Digest{Subject: subject, Body: b.String()}
}
