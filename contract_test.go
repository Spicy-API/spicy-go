package spicy

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestContractHasNotDrifted 钉住这个包写死的契约事实与线上公开契约一致。
//
// 为什么需要它：SDK 里那些枚举、错误码、上限全是从契约抄下来的常量。契约改了而
// 这里没改，不会有任何东西报错——请求照发、响应照解析，只是某个新档位被当成非法值
// 拒在本地，或者某个新错误码被泛化成"未知错误"。这类失效没有信号。
//
// 为什么比对**线上**契约而不是 spicy-server 仓库：这个仓库是公开的，而 spicy-server
// 是私有的。给公开仓库的 CI 配一把能读私有仓库的令牌，等于把那把令牌放在任何人都能
// 提 PR 的地方。契约本身就是公开的，拿公开的比对公开的，零凭据。
func TestContractHasNotDrifted(t *testing.T) {
	local, err := os.ReadFile("contracts/openapi.yaml")
	if err != nil {
		t.Fatalf("read the pinned contract: %v", err)
	}

	if os.Getenv("SPICY_SKIP_LIVE_CONTRACT") == "" {
		live := fetchLiveContract(t)
		if string(local) != live {
			t.Fatalf("contracts/openapi.yaml is stale against the published contract.\n" +
				"refresh it:  curl -sH 'User-Agent: spicyapi-contract-check' " +
				"https://docs.spicyapi.ai/openapi.yaml -o contracts/openapi.yaml\n" +
				"then re-check every constant this package hard-codes against that diff")
		}
	}

	text := string(local)
	// 只放"改了会出事"的那几组。清单短才有人维护。
	assertEnum(t, text, "    TaskRecord:", "state:", []string{
		StateQueued, StateRunning, StateSucceeded, StateFailed, StateCanceled, StateExpired,
	})
	assertEnum(t, text, "    UploadURLRequest:", "contentType:", acceptedUploadTypes)
}

// fetchLiveContract 取线上契约。
//
// **必须带 User-Agent**：docs 站的边缘防护会把没有 UA 或使用默认 UA 的请求拒成 403，
// 而 api 站不会——2026-09-20 实测过两个域名，行为不同。少这一个头，这条用例会以
// "契约漂移"的名义红，而真实原因与契约无关。
func fetchLiveContract(t *testing.T) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://docs.spicyapi.ai/openapi.yaml", nil)
	if err != nil {
		t.Fatalf("build the contract request: %v", err)
	}
	request.Header.Set("User-Agent", "spicyapi-contract-check")

	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Skipf("the published contract is unreachable (%v); run with network access to verify drift", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the published contract answered %d", response.StatusCode)
	}
	body := make([]byte, 0, 128*1024)
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := response.Body.Read(buffer)
		body = append(body, buffer[:n]...)
		if readErr != nil {
			break
		}
	}
	return string(body)
}

var enumPattern = regexp.MustCompile(`enum:\s*\[([^\]]+)\]`)

func assertEnum(t *testing.T, contract, anchor, field string, ours ...[]string) {
	t.Helper()
	start := strings.Index(contract, anchor)
	if start < 0 {
		t.Fatalf("the contract has no %s schema", anchor)
	}
	window := contract[start:min(start+4000, len(contract))]
	at := strings.Index(window, field)
	if at < 0 {
		t.Fatalf("%s has no %s property", anchor, field)
	}
	match := enumPattern.FindStringSubmatch(window[at:min(at+600, len(window))])
	if match == nil {
		t.Fatalf("%s.%s has no enum", anchor, field)
	}

	theirs := make([]string, 0, 8)
	for _, value := range strings.Split(match[1], ",") {
		theirs = append(theirs, strings.Trim(strings.TrimSpace(value), `'"`))
	}

	var flat []string
	for _, group := range ours {
		flat = append(flat, group...)
	}
	sort.Strings(flat)
	sort.Strings(theirs)
	if strings.Join(flat, ",") != strings.Join(theirs, ",") {
		t.Errorf("%s.%s drifted:\n  package:  %v\n  contract: %v", anchor, field, flat, theirs)
	}
}
