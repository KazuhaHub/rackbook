package main

import (
	"fmt"
	"net/url"
	"strings"

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
		expires:  "Expires",
		daysLeft: "Days left",
		source:   "Source",
		manual:   "manual",
		link:     "Link",
		intro:    "These records crossed a reminder threshold:",
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
		expires:  "到期日",
		daysLeft: "剩余天数",
		source:   "来源",
		manual:   "手动",
		link:     "链接",
		intro:    "以下记录已达到提醒阈值：",
	},
}

func itemLink(base string, it rbclient.Item) string {
	return strings.TrimRight(base, "/") + "/c/" + url.PathEscape(it.Collection) + "/" + url.PathEscape(it.ID)
}

func buildDigest(lang, baseURL string, due []rbclient.Item) Digest {
	t, ok := langs[lang]
	if !ok {
		t = langs["en"]
	}
	var expired, expiring int
	var b strings.Builder
	b.WriteString(t.intro + "\n")
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
	return Digest{Subject: t.subject(expired, expiring), Body: b.String()}
}
