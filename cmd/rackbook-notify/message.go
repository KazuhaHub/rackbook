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

type texts struct {
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
}

var langs = map[string]texts{
	"en": {
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
			return "Rackbook: " + strings.Join(parts, ", ")
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
		failedRun: "failed",
	},
	"zh": {
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
			return "Rackbook：" + strings.Join(parts, "，")
		},
		expires:       "到期日",
		daysLeft:      "剩余天数",
		source:        "来源",
		manual:        "手动",
		link:          "链接",
		intro:         "以下记录已达到提醒阈值：",
		failedIntro:   "以下模块运行失败：",
		failedSubject: func(n int) string { return fmt.Sprintf("%d 个模块运行失败", n) },
		failedRun:     "失败",
	},
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
	t, ok := langs[lang]
	if !ok {
		t = langs["en"]
	}
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
	subject := ""
	if len(due) > 0 {
		subject = t.subject(expired, expiring)
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
		fs := t.failedSubject(len(failed))
		if subject == "" {
			if lang == "zh" {
				subject = "Rackbook：" + fs
			} else {
				subject = "Rackbook: " + fs
			}
		} else if lang == "zh" {
			subject += "，" + fs
		} else {
			subject += ", " + fs
		}
	}
	return Digest{Subject: subject, Body: b.String()}
}
