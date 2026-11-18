package export_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/export"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func load(t *testing.T) *ledger.Ledger {
	return ledger.Load(testutil.LoadConfig(t, testutil.CopyExample(t)), nil)
}

func TestMarkdown(t *testing.T) {
	l := load(t)
	md := export.Markdown(l)
	for _, want := range []string{
		"# 示例网络台账\n",
		"## 设备\n",
		"| 设备名 | 类别 | 站点 / 服务商 | 系统 | 公网 IPv4 | IPv4 类型 | 公网 IPv6 | 公网域名 | 纳管 | 备注 |",
		"| web-hostco-ashburn-va-us-dc | 公开服务器（海外） | HostCo Ashburn, VA | Ubuntu 26.04 | 198.51.100.20 | 静态 | 2001:db8:20::1 | web.hostco.ashburn.va.us.dc.example.com | ✓ | 主站、证书中心 |",
		"## 网段规划\n\n### Tailscale 网段\n",
		"### Docker / 虚拟机网段\n\n> **Docker 地址池规则**\n> Docker 地址池只用于本机容器",
		"由配置仓库管理；编辑会提交到 Git 并推送； 只有 Cloudflare Access 放行的人能打开",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
	if strings.Count(md, "## 网段规划") != 1 {
		t.Error("group heading must appear once")
	}
	if md != export.Markdown(l) {
		t.Error("not deterministic")
	}
}

func TestMarkdownEscapes(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 统一代理入站端口, scope: web + standby, status: 推迟}", `{item: "a | b\nc", scope: x, status: 推迟}`)
	md := export.Markdown(ledger.Load(testutil.LoadConfig(t, dir), nil))
	if !strings.Contains(md, `| a \| b<br>c | x | 推迟 |`) {
		t.Fatal(md)
	}
}

func TestLLMS(t *testing.T) {
	l := load(t)
	with := export.LLMS(l, "https://ledger.example.com/")
	for _, want := range []string{"# 示例网络台账\n", "> 设备、内网地址", "- [设备](https://ledger.example.com/api/c/devices): 所有设备（服务器、路由器、终端、NAS）。 (5 records)", "[Everything as Markdown](https://ledger.example.com/llms-full.txt)"} {
		if !strings.Contains(with, want) {
			t.Errorf("missing %q in:\n%s", want, with)
		}
	}
	without := export.LLMS(l, "")
	if strings.Contains(without, "http") || !strings.Contains(without, "- 设备 (devices): ") {
		t.Fatal(without)
	}
}

func TestJSON(t *testing.T) {
	l := load(t)
	b, err := export.JSON(l)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Title       string                      `json:"title"`
		Collections map[string][]map[string]any `json:"collections"`
		Notes       []map[string]string         `json:"notes"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Title != "示例网络台账" || len(out.Collections["devices"]) != 5 || len(out.Notes) != 2 || out.Notes[0]["collection"] != "docker_ranges" {
		t.Fatalf("%+v", out)
	}
	// Collections come out in config order, fields in schema order.
	s := string(b)
	if strings.Index(s, `"devices"`) > strings.Index(s, `"addresses"`) || strings.Index(s, `"name"`) > strings.Index(s, `"category"`) {
		t.Fatal("order lost")
	}
}
