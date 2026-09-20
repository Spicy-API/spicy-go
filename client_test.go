package spicy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 这四条用例各自钉住一个**能反证**的性质：把对应的修复删掉，它必须变红。
// 断言的都是外部可观察的行为（错误文本、错误身份、发出去的请求头、轮询次数），
// 不是实现细节，所以重写实现不会让它们无谓地红。

// ── 1. 预签名上传 URL 不许进错误文本 ─────────────────────────────────────

// 这两个值只出现在票据 URL 的 query 里。它们出现在任何错误文本里都是泄漏。
const (
	testUploadSignature  = "DEADBEEFcafef00d0123456789abcdef0123456789abcdef0123456789abcdef"
	testUploadCredential = "AKIAIOSFODNN7EXAMPLE%2F20260920%2Fauto%2Fs3%2Faws4_request"
)

// bodyOf 把一段 JSON 包成可读的响应体。
func bodyOf(payload string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(payload))
}

// TestUploadFailureKeepsThePresignedURLOutOfItsMessage 证明一次失败的上传不会
// 把对象存储的写入授权印进错误里。
//
// 为什么这条值得单独一个用例：那个 URL 是一张大约 20 分钟有效的**写入**凭据，
// 签名和访问密钥都在 query 里，而 http.Client.Do 失败时返回的 *url.Error 默认
// 会把它整串印出来。这行字通常直接进应用日志，于是凭据的有效期变成了"日志的
// 保留期"。失效完全没有信号：上传报错是个再正常不过的日志条目。
func TestUploadFailureKeepsThePresignedURLOutOfItsMessage(t *testing.T) {
	// 立刻关掉的监听器：它的地址保证连不上，于是必然产生一个 *url.Error。
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	presigned := deadURL + "/spicy-uploads/fil_abc123.png" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=" + testUploadCredential +
		"&X-Amz-Date=20260920T000000Z&X-Amz-Expires=1200&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=" + testUploadSignature

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":200,"msg":"ok","request_id":"req_1","data":{
			"fileId":"fil_abc123","uploadUrl":%q,"method":"PUT",
			"headers":{"Content-Type":"image/png"},
			"expiresAt":"2030-01-01T00:00:00Z","maxBytes":10485760}}`, presigned)
	}))
	defer api.Close()

	client, err := New(Options{APIKey: "sk-test", BaseURL: api.URL})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	_, err = client.Upload(context.Background(), []byte("not really a png"), "image/png")
	if err == nil {
		t.Fatal("uploading to a dead address should fail")
	}
	message := err.Error()

	for _, secret := range []string{
		testUploadSignature,
		testUploadCredential,
		"X-Amz-Signature",
		"X-Amz-Credential",
		presigned,
	} {
		if strings.Contains(message, secret) {
			t.Errorf("the upload error leaks %q.\n  message: %s", secret, message)
		}
	}

	// 反向断言：不能靠"把错误清空"来通过上面那段。错误还得说清楚出了什么事，
	// 否则超时、连接被拒、TLS 握手失败在生产里就长得一模一样了。
	if !strings.Contains(message, "uploading to object storage") {
		t.Errorf("the upload error stopped saying what failed: %s", message)
	}
	if !strings.Contains(message, "connection refused") {
		t.Errorf("the upload error stopped saying why it failed: %s", message)
	}

	// 原因还要留在错误链里，否则调用方分不出"上传超时了"和"上传被拒了"。
	if errors.Unwrap(err) == nil {
		t.Error("the upload error has no cause left in its chain")
	}
}

// TestRedactedUploadErrorStillReportsATimeout 钉住脱敏没有顺手切断错误链：
// 十分钟的上传预算用尽时，调用方要能用 errors.Is 认出这是超时。
func TestRedactedUploadErrorStillReportsATimeout(t *testing.T) {
	signed := "https://storage.example/put?X-Amz-Signature=" + testUploadSignature
	wrapped := withoutSignedURL(&urlErrorStub{op: "Put", url: signed, err: context.DeadlineExceeded}, signed)

	if !errors.Is(wrapped, context.DeadlineExceeded) {
		t.Errorf("redaction broke errors.Is for a timeout: %v", wrapped)
	}
	if strings.Contains(wrapped.Error(), testUploadSignature) {
		t.Errorf("redaction let the signature through: %s", wrapped.Error())
	}
}

// urlErrorStub 复刻 *url.Error 的渲染方式，好让上面那条用例不必真的建连接。
type urlErrorStub struct {
	op  string
	url string
	err error
}

func (e *urlErrorStub) Error() string {
	return e.op + " " + strconv.Quote(e.url) + ": " + e.err.Error()
}
func (e *urlErrorStub) Unwrap() error { return e.err }

// ── 2. 先验签名，再判新鲜度 ──────────────────────────────────────────────

func signWebhook(t *testing.T, secret, taskID, timestamp string, body []byte) string {
	t.Helper()
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(taskID + "." + timestamp + "." + hex.EncodeToString(digest[:])))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func webhookHeader(version, timestamp, signature string) http.Header {
	header := http.Header{}
	header.Set("X-Webhook-Payload-Version", version)
	header.Set("X-Webhook-Timestamp", timestamp)
	header.Set("X-Webhook-Signature", signature)
	return header
}

// TestWebhookRejectsABadSignatureBeforeCallingItStale 证明一条**既伪造又过期**的
// 投递被报成签名错误，而不是过期。
//
// 两种顺序都不会放行这条投递，所以这不是"验不出来"。危害在于告警指向错了方向：
// 伪造者自己填时间戳，随手填个旧的就会被报成"过期"。运维看到满屏"过期"，
// 合理反应是调宽 tolerance——而那正是把这些投递从"被拒"推向"被接受"的旋钮。
// 于是一次攻击先伪装成时钟问题，再被我们自己亲手放行。
func TestWebhookRejectsABadSignatureBeforeCallingItStale(t *testing.T) {
	const secret = "whsec_test"
	body := []byte(`{"task_id":"task_real","state":"succeeded"}`)
	stale := strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10)

	header := webhookHeader("1", stale, "dGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ==")
	_, err := VerifyWebhook(secret, header, body, 5*time.Minute)

	if !errors.Is(err, ErrWebhookSignature) {
		t.Errorf("a forged delivery must be reported as a signature failure, got %v", err)
	}
	if errors.Is(err, ErrWebhookStale) {
		t.Errorf("a forged delivery was reported as merely stale, which is the alert that "+
			"makes an operator widen the tolerance window: %v", err)
	}
}

// TestWebhookStillRejectsAnAuthenticButStaleDelivery 是上一条的反面：调换顺序
// 不等于把新鲜度检查删掉。签名对、时间戳旧，仍然要被判过期——重放防护还在。
func TestWebhookStillRejectsAnAuthenticButStaleDelivery(t *testing.T) {
	const secret = "whsec_test"
	body := []byte(`{"task_id":"task_real","state":"succeeded"}`)
	stale := strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10)

	header := webhookHeader("1", stale, signWebhook(t, secret, "task_real", stale, body))
	_, err := VerifyWebhook(secret, header, body, 5*time.Minute)

	if !errors.Is(err, ErrWebhookStale) {
		t.Errorf("a genuine but old delivery must still be rejected as stale, got %v", err)
	}
}

// TestWebhookAcceptsAFreshAuthenticDelivery 守住"两条检查都还在做事"的下界。
func TestWebhookAcceptsAFreshAuthenticDelivery(t *testing.T) {
	const secret = "whsec_test"
	body := []byte(`{"task_id":"task_real","state":"succeeded"}`)
	now := strconv.FormatInt(time.Now().Unix(), 10)

	header := webhookHeader("1", now, signWebhook(t, secret, "task_real", now, body))
	taskID, err := VerifyWebhook(secret, header, body, 5*time.Minute)

	if err != nil {
		t.Fatalf("a fresh authentic delivery must verify: %v", err)
	}
	if taskID != "task_real" {
		t.Errorf("verified task id = %q, want task_real", taskID)
	}
}

// ── 3. 每一发请求都带版本号 ─────────────────────────────────────────────

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// TestEveryRequestIdentifiesItselfWithAVersionedUserAgent 证明请求带得出版本号。
//
// 没有它 net/http 发的是 Go-http-client/1.1，那句话只说明"对方是个 Go 程序"。
// 于是"哪些客户端受这个 bug 影响"这种问题从查日志变成了猜。
func TestEveryRequestIdentifiesItselfWithAVersionedUserAgent(t *testing.T) {
	var seen string
	client, err := New(Options{
		APIKey:  "sk-test",
		BaseURL: "https://api.example.invalid/api/v1",
		HTTPClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			seen = req.Header.Get("User-Agent")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       bodyOf(`{"code":200,"msg":"ok","request_id":"r","data":{"taskId":"t"}}`),
				Request:    req,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	if _, err := client.GetTask(context.Background(), "task_1"); err != nil {
		t.Fatalf("GetTask: %v", err)
	}

	if seen == "" {
		t.Fatal("the request sent no User-Agent, so net/http substituted Go-http-client/1.1")
	}
	if strings.HasPrefix(seen, "Go-http-client") {
		t.Fatalf("the request went out as the net/http default %q", seen)
	}
	if want := "SpicyAPI-Go/" + Version; seen != want {
		t.Errorf("User-Agent = %q, want %q", seen, want)
	}
	// 版本号必须真的是个版本号：空串拼上去也满足上面那条相等。
	if strings.TrimSpace(Version) == "" || !strings.Contains(seen, ".") {
		t.Errorf("User-Agent %q carries no version number", seen)
	}
}

// TestCallerHeadersStillWin 钉住 User-Agent 是默认值而不是硬写死的：把这个
// 客户端嵌进自己 SDK 的人要能改掉它。
func TestCallerHeadersStillWin(t *testing.T) {
	var seen string
	client, err := New(Options{
		APIKey:  "sk-test",
		BaseURL: "https://api.example.invalid/api/v1",
		HTTPClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			seen = req.Header.Get("Idempotency-Key")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       bodyOf(`{"code":200,"msg":"ok","request_id":"r","data":{"taskId":"t","state":"queued"}}`),
				Request:    req,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	_, err = client.CreateTask(context.Background(), CreateTaskInput{
		Model: "m", Input: map[string]any{"prompt": "p"},
	}, "spicy-deadbeef", CreateTaskOptions{})
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if seen != "spicy-deadbeef" {
		t.Errorf("Idempotency-Key = %q, want spicy-deadbeef", seen)
	}
}

// ── 5. 单发轮询超时不终结整次等待 ───────────────────────────────────────

// hangingDoer 模拟"服务器收了请求但不答"：每一发都挂到该发自己的请求超时为止。
type hangingDoer struct{ calls atomic.Int64 }

func (d *hangingDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestWaitForTerminalKeepsPollingWhenOnePollTimesOut 证明一次轮询超时不会把
// 整次等待毙掉，而预算真正耗尽时报出来的错误带着 taskID。
//
// 两件事都要紧。一是十分钟的预算不该因为第一发卡满三十秒就放弃——任务还在跑、
// 还在计费。二是那个错误必须是 *WaitTimeoutError：文档告诉调用方"本地超时不是
// 判决，留着 task ID 去对账"，而一个裸的传输错误上没有 TaskID 字段，恰好在最
// 需要这个编号的时刻把它弄丢。
func TestWaitForTerminalKeepsPollingWhenOnePollTimesOut(t *testing.T) {
	doer := &hangingDoer{}
	client, err := New(Options{
		APIKey:     "sk-test",
		BaseURL:    "https://api.example.invalid/api/v1",
		HTTPClient: doer,
		// 把刻度压小，好让一条真实预算的等待在半秒内跑完。语义不变：
		// 每一发都在自己的请求超时上失败，而总预算远大于单发超时。
		RequestTimeout: 20 * time.Millisecond,
		MaxRetries:     -1, // 关掉 do() 自己的重试，好让轮询次数只反映这个循环
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	started := time.Now()
	_, waitErr := client.WaitForTerminal(context.Background(), "task_abc123", WaitOptions{
		Timeout:     400 * time.Millisecond,
		Interval:    5 * time.Millisecond,
		MaxInterval: 5 * time.Millisecond,
	})
	elapsed := time.Since(started)

	if polls := doer.calls.Load(); polls < 4 {
		t.Errorf("only %d poll(s) in a 400ms budget of 20ms requests: one timed-out poll "+
			"ended the whole wait", polls)
	}
	if elapsed < 300*time.Millisecond {
		t.Errorf("the wait gave up after %v of a 400ms budget", elapsed.Round(time.Millisecond))
	}

	var timeout *WaitTimeoutError
	if !errors.As(waitErr, &timeout) {
		t.Fatalf("a spent wait budget must report *WaitTimeoutError, got %T: %v", waitErr, waitErr)
	}
	if timeout.TaskID != "task_abc123" {
		t.Errorf("the wait timeout lost the task id: %+v", timeout)
	}
}

// TestWaitForTerminalStopsOnAnAnswerFromTheServer 是上一条的反面：吞掉的只能是
// 超时。服务端给出的判决（这里是 404）要立刻还给调用方，反复轮询一个明确的
// 拒绝只会把它拖成十分钟的沉默。
func TestWaitForTerminalStopsOnAnAnswerFromTheServer(t *testing.T) {
	var polls atomic.Int64
	client, err := New(Options{
		APIKey:  "sk-test",
		BaseURL: "https://api.example.invalid/api/v1",
		HTTPClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			polls.Add(1)
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       bodyOf(`{"code":40401,"msg":"task not found","request_id":"r","data":null}`),
				Request:    req,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	_, waitErr := client.WaitForTerminal(context.Background(), "task_gone", WaitOptions{
		Timeout:     2 * time.Second,
		Interval:    5 * time.Millisecond,
		MaxInterval: 5 * time.Millisecond,
	})

	var apiErr *APIError
	if !errors.As(waitErr, &apiErr) {
		t.Fatalf("a 404 must end the wait as *APIError, got %T: %v", waitErr, waitErr)
	}
	if got := polls.Load(); got != 1 {
		t.Errorf("a 404 was polled %d times; an answer from the server is not a blip", got)
	}
}

// TestWaitForTerminalReturnsTheCallersOwnCancellation 守住第三种情形没有被上面
// 两条吃掉：调用方自己取消时，还回去的是他自己的错误，不是我们的本地超时。
func TestWaitForTerminalReturnsTheCallersOwnCancellation(t *testing.T) {
	doer := &hangingDoer{}
	client, err := New(Options{
		APIKey:         "sk-test",
		BaseURL:        "https://api.example.invalid/api/v1",
		HTTPClient:     doer,
		RequestTimeout: time.Second,
		MaxRetries:     -1,
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	_, waitErr := client.WaitForTerminal(ctx, "task_abc123", WaitOptions{Timeout: 10 * time.Second})

	if !errors.Is(waitErr, context.Canceled) {
		t.Errorf("a cancelled caller must get context.Canceled back, got %v", waitErr)
	}
	var timeout *WaitTimeoutError
	if errors.As(waitErr, &timeout) {
		t.Errorf("a cancelled caller was told our local budget ran out: %v", waitErr)
	}
}

// ── 新增端点：/chat/credit、/usage、/jobs ────────────────────────────────

// recordingAPI 起一个假 API，逐条记下收到的 method + path（含 query），
// 并按顺序回放给定的响应体。
type recordingAPI struct {
	server    *httptest.Server
	mu        sync.Mutex
	requests  []string
	responses []string
}

func newRecordingAPI(t *testing.T, responses ...string) *recordingAPI {
	t.Helper()
	api := &recordingAPI{responses: responses}
	api.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.requests = append(api.requests, r.Method+" "+r.URL.RequestURI())
		body := `{"code":200,"msg":"success","request_id":"r","data":{}}`
		if n := len(api.requests) - 1; n < len(api.responses) {
			body = api.responses[n]
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(api.server.Close)
	return api
}

func (a *recordingAPI) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...)
}

func (a *recordingAPI) client(t *testing.T) *Client {
	t.Helper()
	client, err := New(Options{APIKey: "sk-test", BaseURL: a.server.URL})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}
	return client
}

// businessFailureAPI 回 HTTP 200 而信封里的 code 不是 200。
//
// 这是这个平台最容易被写错的一处：传输层成功不等于调用成功。把它当成功，
// 调用方拿到的是一个零值结构体——余额 ""、用量 0、任务列表空——而那些零值
// 每一个都是"看起来合理"的答案。所以三个新端点各配一条。
func businessFailureAPI(t *testing.T, code int, msg string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":%d,"msg":%q,"request_id":"req_x","data":null}`, code, msg)
	}))
	t.Cleanup(server.Close)
	client, err := New(Options{APIKey: "sk-test", BaseURL: server.URL, MaxRetries: -1})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}
	return client
}

func TestGetBalance(t *testing.T) {
	api := newRecordingAPI(t, `{"code":200,"msg":"success","request_id":"r","data":{
		"available":"12.3456","held":"0.5000","total":"12.8456",
		"funding":{"balanceUsd":"10.0000","heldUsd":"0.5000",
			"prepaidAvailableUsd":"10.0000","grantAvailableUsd":"2.3456",
			"cashShortfallUsd":"0","grantsHasMore":false,
			"credit":{"enabled":true,"limitUsd":"100.0000","availableUsd":"100.0000",
				"usedUsd":"0","heldUsd":"0","status":"active","version":3,"expiresAt":null},
			"grants":[{"id":"gr_1","name":"Launch credit","amountUsd":"5.0000",
				"availableUsd":"2.3456","heldUsd":"0","spentUsd":"2.6544","status":"active",
				"startsAt":"2026-09-01T00:00:00Z","expiresAt":null,
				"modelSlugs":[],"customerMemo":"welcome","createdAt":"2026-09-01T00:00:00Z"}]}}}`)

	balance, err := api.client(t).GetBalance(context.Background())
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}

	if got := api.seen(); len(got) != 1 || got[0] != "GET /chat/credit" {
		t.Errorf("requests = %v, want one GET /chat/credit", got)
	}
	if balance.Available != "12.3456" || balance.Held != "0.5000" || balance.Total != "12.8456" {
		t.Errorf("balance = %+v", balance)
	}
	if balance.Funding == nil {
		t.Fatal("the funding breakdown was dropped")
	}
	if balance.Funding.GrantAvailableUsd != "2.3456" {
		t.Errorf("grantAvailableUsd = %q", balance.Funding.GrantAvailableUsd)
	}
	if balance.Funding.Credit == nil || balance.Funding.Credit.LimitUsd != "100.0000" {
		t.Errorf("credit facility = %+v", balance.Funding.Credit)
	}
	if balance.Funding.Credit.Version != 3 {
		t.Errorf("credit version = %d, want 3", balance.Funding.Credit.Version)
	}
	if len(balance.Funding.Grants) != 1 || balance.Funding.Grants[0].ID != "gr_1" {
		t.Fatalf("grants = %+v", balance.Funding.Grants)
	}
	// 空的 modelSlugs 表示"所有模型"，不是"没有模型"。解码后必须仍然是空的，
	// 而不是被当成缺字段丢掉——调用方要靠 len()==0 判断这件事。
	if got := balance.Funding.Grants[0].ModelSlugs; len(got) != 0 {
		t.Errorf("modelSlugs = %v, want empty (which means every model)", got)
	}
	if balance.Funding.Grants[0].ExpiresAt != nil {
		t.Errorf("a null expiresAt must decode to nil, got %v", balance.Funding.Grants[0].ExpiresAt)
	}
}

func TestGetBalanceDoesNotTreatABusinessFailureAsSuccess(t *testing.T) {
	_, err := businessFailureAPI(t, 40301, "key cannot read balances").
		GetBalance(context.Background())

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("HTTP 200 with a non-200 business code must be an *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != 40301 {
		t.Errorf("code = %d, want 40301", apiErr.Code)
	}
	if apiErr.RequestID != "req_x" {
		t.Errorf("request id = %q, want req_x", apiErr.RequestID)
	}
}

func TestGetUsage(t *testing.T) {
	api := newRecordingAPI(t, `{"code":200,"msg":"success","request_id":"r","data":{
		"from":"2026-09-01","to":"2026-09-08","currency":"USD",
		"totalCalls":42,"totalSpend":"3.1400",
		"days":[{"day":"2026-09-01","calls":2,"succeeded":1,"failed":1,"spend":"0.2000"}],
		"models":[{"model":"bytedance/seedance-2.5/text-to-video",
			"calls":40,"succeeded":40,"failed":0,"spend":"2.9400"}]}}`)

	usage, err := api.client(t).GetUsage(context.Background(), UsageOptions{
		From: "2026-09-01", To: "2026-09-08",
	})
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}

	if got := api.seen(); len(got) != 1 || got[0] != "GET /usage?from=2026-09-01&to=2026-09-08" {
		t.Errorf("requests = %v", got)
	}
	if usage.TotalCalls != 42 || usage.TotalSpend != "3.1400" || usage.Currency != "USD" {
		t.Errorf("usage = %+v", usage)
	}
	// 服务端回的窗口要读得到：不填 From/To 时它自己挑，这里是唯一说明挑了什么的地方。
	if usage.From != "2026-09-01" || usage.To != "2026-09-08" {
		t.Errorf("window = [%s,%s)", usage.From, usage.To)
	}
	if len(usage.Days) != 1 || usage.Days[0].Failed != 1 {
		t.Errorf("days = %+v", usage.Days)
	}
	if len(usage.Models) != 1 || usage.Models[0].Spend != "2.9400" {
		t.Errorf("models = %+v", usage.Models)
	}
}

// TestGetUsageOmitsEmptyDates 钉住"没设"不会变成空参数——契约明说空的 query
// 参数会被拒。
func TestGetUsageOmitsEmptyDates(t *testing.T) {
	api := newRecordingAPI(t)
	if _, err := api.client(t).GetUsage(context.Background(), UsageOptions{}); err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if got := api.seen(); len(got) != 1 || got[0] != "GET /usage" {
		t.Errorf("requests = %v, want a bare GET /usage with no query at all", got)
	}
}

func TestGetUsageDoesNotTreatABusinessFailureAsSuccess(t *testing.T) {
	_, err := businessFailureAPI(t, 40001, "date range exceeds 92 days").
		GetUsage(context.Background(), UsageOptions{From: "2020-01-01", To: "2026-01-01"})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("HTTP 200 with a non-200 business code must be an *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != 40001 {
		t.Errorf("code = %d, want 40001", apiErr.Code)
	}
}

func TestListTasks(t *testing.T) {
	api := newRecordingAPI(t, `{"code":200,"msg":"success","request_id":"r","data":{
		"items":[{"taskId":"task_1","model":"m","state":"succeeded","cost":"0.1200",
			"settled":true,"createdAt":"2026-09-20T10:00:00Z",
			"deadlineAt":"2026-09-20T10:30:00Z","completedAt":"2026-09-20T10:02:00Z"},
			{"taskId":"task_2","model":"m","state":"running","cost":"0.1200",
			"settled":false,"createdAt":"2026-09-20T11:00:00Z",
			"deadlineAt":"2026-09-20T11:30:00Z"}],
		"hasMore":true,"nextCursor":"cur_page2"}}`)

	list, err := api.client(t).ListTasks(context.Background(), ListTasksOptions{
		From: "2026-09-01", To: "2026-09-21", State: StateSucceeded, Model: "m", Limit: 50,
	})
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}

	want := "GET /jobs?from=2026-09-01&limit=50&model=m&state=succeeded&to=2026-09-21"
	if got := api.seen(); len(got) != 1 || got[0] != want {
		t.Errorf("requests = %v\n  want %s", got, want)
	}
	if len(list.Items) != 2 {
		t.Fatalf("items = %+v", list.Items)
	}
	if !list.HasMore || list.NextCursor != "cur_page2" {
		t.Errorf("hasMore = %v, nextCursor = %q", list.HasMore, list.NextCursor)
	}
	if !list.Items[0].Settled || list.Items[0].CompletedAt == nil {
		t.Errorf("settled row = %+v", list.Items[0])
	}
	// 在途的行没有 completedAt。它必须是 nil，而不是零值时间——零值时间是
	// 0001-01-01，打印出来像一条 2000 年前完成的任务。
	if list.Items[1].CompletedAt != nil {
		t.Errorf("an in-flight row must have a nil CompletedAt, got %v", list.Items[1].CompletedAt)
	}
}

// TestListTasksOmitsUnsetFilters 钉住零值不会变成空 query 参数，以及 Limit 的
// 零值是"没设"而不是"要 0 条"。
func TestListTasksOmitsUnsetFilters(t *testing.T) {
	api := newRecordingAPI(t)
	if _, err := api.client(t).ListTasks(context.Background(), ListTasksOptions{}); err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if got := api.seen(); len(got) != 1 || got[0] != "GET /jobs" {
		t.Errorf("requests = %v, want a bare GET /jobs", got)
	}
}

// TestListTasksDoesNotCapTheLimitLocally 钉住上限不在本地判。服务端把它放宽到
// 200 的那天，这个包不该替用户拒绝一个已经能用的值。
func TestListTasksDoesNotCapTheLimitLocally(t *testing.T) {
	api := newRecordingAPI(t)
	if _, err := api.client(t).ListTasks(context.Background(), ListTasksOptions{Limit: 500}); err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if got := api.seen(); len(got) != 1 || got[0] != "GET /jobs?limit=500" {
		t.Errorf("requests = %v; the limit must reach the server, which is the only "+
			"place that knows the real bound", got)
	}
}

func TestListTasksDoesNotTreatABusinessFailureAsSuccess(t *testing.T) {
	_, err := businessFailureAPI(t, 40001, "unknown query parameter").
		ListTasks(context.Background(), ListTasksOptions{Limit: 20})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("HTTP 200 with a non-200 business code must be an *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != 40001 {
		t.Errorf("code = %d, want 40001", apiErr.Code)
	}
}

// TestEachTaskRepeatsEveryFilterAndOnlyMovesTheCursor 是分页语义那条的核心：
// 游标只对签发它的那次查询有意义，走到一半改掉任何一个筛选条件，拿回来的页
// 两次查询都不属于——而且没有任何东西会报错。
func TestEachTaskRepeatsEveryFilterAndOnlyMovesTheCursor(t *testing.T) {
	api := newRecordingAPI(t,
		`{"code":200,"msg":"success","request_id":"r","data":{
			"items":[{"taskId":"task_1","model":"m","state":"succeeded","cost":"0.1",
				"settled":true,"createdAt":"2026-09-20T10:00:00Z","deadlineAt":"2026-09-20T10:30:00Z"}],
			"hasMore":true,"nextCursor":"cur_2"}}`,
		`{"code":200,"msg":"success","request_id":"r","data":{
			"items":[{"taskId":"task_2","model":"m","state":"succeeded","cost":"0.1",
				"settled":true,"createdAt":"2026-09-20T09:00:00Z","deadlineAt":"2026-09-20T09:30:00Z"}],
			"hasMore":false}}`,
	)

	var walked []string
	err := api.client(t).EachTask(context.Background(), ListTasksOptions{
		From: "2026-09-01", To: "2026-09-21", State: StateSucceeded, Model: "m", Limit: 1,
	}, func(item TaskListItem) bool {
		walked = append(walked, item.TaskID)
		return true
	})
	if err != nil {
		t.Fatalf("EachTask: %v", err)
	}

	if strings.Join(walked, ",") != "task_1,task_2" {
		t.Errorf("walked %v, want both pages in order", walked)
	}
	base := "from=2026-09-01&limit=1&model=m&state=succeeded&to=2026-09-21"
	want := []string{
		"GET /jobs?" + base,
		"GET /jobs?cursor=cur_2&" + base,
	}
	got := api.seen()
	if len(got) != len(want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request #%d = %s\n  want %s", i+1, got[i], want[i])
		}
	}
}

// TestEachTaskStopsWhenTheCallerSaysSo 证明提前退出不会继续翻页——每一页都是
// 一次真实的接口调用。
func TestEachTaskStopsWhenTheCallerSaysSo(t *testing.T) {
	api := newRecordingAPI(t, `{"code":200,"msg":"success","request_id":"r","data":{
		"items":[{"taskId":"task_1","model":"m","state":"queued","cost":"0.1",
			"settled":false,"createdAt":"2026-09-20T10:00:00Z","deadlineAt":"2026-09-20T10:30:00Z"},
			{"taskId":"task_2","model":"m","state":"queued","cost":"0.1",
			"settled":false,"createdAt":"2026-09-20T10:00:00Z","deadlineAt":"2026-09-20T10:30:00Z"}],
		"hasMore":true,"nextCursor":"cur_2"}}`)

	var seen int
	if err := api.client(t).EachTask(context.Background(), ListTasksOptions{},
		func(TaskListItem) bool { seen++; return false }); err != nil {
		t.Fatalf("EachTask: %v", err)
	}
	if seen != 1 {
		t.Errorf("fn ran %d times after returning false once", seen)
	}
	if got := api.seen(); len(got) != 1 {
		t.Errorf("EachTask kept paging after the caller stopped: %v", got)
	}
}

// TestEachTaskStopsOnAMissingCursor 钉住那条 || ：hasMore 说还有、而 nextCursor
// 是空的时候必须停。只信 hasMore 的话这里是无限翻页——一直调接口，看起来像卡住。
func TestEachTaskStopsOnAMissingCursor(t *testing.T) {
	api := newRecordingAPI(t, `{"code":200,"msg":"success","request_id":"r","data":{
		"items":[],"hasMore":true}}`)

	if err := api.client(t).EachTask(context.Background(), ListTasksOptions{},
		func(TaskListItem) bool { return true }); err != nil {
		t.Fatalf("EachTask: %v", err)
	}
	if got := api.seen(); len(got) != 1 {
		t.Errorf("hasMore without a cursor must end the walk, made %d requests", len(got))
	}
}

func TestEachTaskReportsAFailedPage(t *testing.T) {
	err := businessFailureAPI(t, 50301, "no usable deployment").
		EachTask(context.Background(), ListTasksOptions{}, func(TaskListItem) bool { return true })

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("a failed page must surface as *APIError, got %T: %v", err, err)
	}
}

// ── X-Spicy-Retention ───────────────────────────────────────────────────

// TestRetentionHeaderIsSentVerbatim 钉住留存时长原样送出去，**本地不判上限**。
// 平台上限只有服务端知道，抄一份到这里就是埋一个会过期的常量：服务端放宽之后，
// 这个包会替用户拒绝一个他本来可以用的值。超上限由服务端夹紧，生效值从
// Task.Retention 读回来。
func TestRetentionHeaderIsSentVerbatim(t *testing.T) {
	for _, seconds := range []int{0, 3600, 999999999} {
		var seen string
		client, err := New(Options{
			APIKey:  "sk-test",
			BaseURL: "https://api.example.invalid/api/v1",
			HTTPClient: doerFunc(func(req *http.Request) (*http.Response, error) {
				seen = req.Header.Get("X-Spicy-Retention")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       bodyOf(`{"code":200,"msg":"ok","request_id":"r","data":{"taskId":"t","state":"queued"}}`),
					Request:    req,
				}, nil
			}),
		})
		if err != nil {
			t.Fatalf("build a client: %v", err)
		}

		retention := seconds
		_, err = client.CreateTask(context.Background(), CreateTaskInput{
			Model: "m", Input: map[string]any{"prompt": "p"},
		}, "spicy-deadbeef", CreateTaskOptions{RetentionSeconds: &retention})
		if err != nil {
			t.Fatalf("CreateTask with retention %d: %v", seconds, err)
		}
		if want := strconv.Itoa(seconds); seen != want {
			t.Errorf("X-Spicy-Retention = %q, want %q", seen, want)
		}
	}
}

// TestRetentionHeaderIsAbsentWhenUnset 钉住 0 是个有意义的值，所以"没设"必须
// 用 nil 表达——空的 options 不能悄悄声明"产物立刻删掉"。
func TestRetentionHeaderIsAbsentWhenUnset(t *testing.T) {
	sent := true
	client, err := New(Options{
		APIKey:  "sk-test",
		BaseURL: "https://api.example.invalid/api/v1",
		HTTPClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			_, sent = req.Header["X-Spicy-Retention"]
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       bodyOf(`{"code":200,"msg":"ok","request_id":"r","data":{"taskId":"t","state":"queued"}}`),
				Request:    req,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	if _, err := client.CreateTask(context.Background(), CreateTaskInput{
		Model: "m", Input: map[string]any{"prompt": "p"},
	}, "spicy-deadbeef", CreateTaskOptions{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if sent {
		t.Error("an empty CreateTaskOptions sent X-Spicy-Retention; 0 seconds means " +
			"'delete the outputs the moment the task ends', which is not a default")
	}
}

func TestNegativeRetentionIsRejectedLocally(t *testing.T) {
	client, err := New(Options{APIKey: "sk-test", BaseURL: "https://api.example.invalid/api/v1"})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}
	negative := -1
	_, err = client.CreateTask(context.Background(), CreateTaskInput{
		Model: "m", Input: map[string]any{"prompt": "p"},
	}, "spicy-deadbeef", CreateTaskOptions{RetentionSeconds: &negative})
	if err == nil {
		t.Fatal("a negative retention must be refused before it reaches the network")
	}
}

// ── createTask 的 wait 参数 ─────────────────────────────────────────────

// waitAPI 起一个假 createTask：记下收到的 query，按 hold 握住连接，
// 再按 status 回 200 的任务记录或 202 的受理回执。
func waitAPI(t *testing.T, status int, hold time.Duration) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RequestURI())
		mu.Unlock()
		if hold > 0 {
			time.Sleep(hold)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			// 200 的体是完整任务记录，和 recordInfo 一样的形状。
			_, _ = w.Write([]byte(`{"code":200,"msg":"success","request_id":"r","data":{
				"taskId":"task_1","model":"m","state":"succeeded","cost":"0.1200","settled":true,
				"createdAt":"2026-09-20T10:00:00Z","completedAt":"2026-09-20T10:00:05Z",
				"output":{"assets":[{"key":"a","url":"https://cdn.example/a.mp4"}]}}}`))
			return
		}
		// 202 的体是受理回执，形状完全不同：有 estimatedCost，没有 cost。
		_, _ = w.Write([]byte(`{"code":200,"msg":"success","request_id":"r","data":{
			"taskId":"task_1","state":"queued","estimatedCost":"0.1200",
			"deadlineAt":"2026-09-20T10:30:00Z"}}`))
	}))
	t.Cleanup(server.Close)
	return server, &queries
}

func waitClient(t *testing.T, server *httptest.Server, requestTimeout time.Duration, maxRetries int) *Client {
	t.Helper()
	client, err := New(Options{
		APIKey: "sk-test", BaseURL: server.URL,
		RequestTimeout: requestTimeout, MaxRetries: maxRetries,
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}
	return client
}

func createWith(t *testing.T, client *Client, opts CreateTaskOptions) (*CreateTaskResult, error) {
	t.Helper()
	return client.CreateTask(context.Background(), CreateTaskInput{
		Model: "m", Input: map[string]any{"prompt": "p"},
	}, "spicy-deadbeef", opts)
}

// TestWaitSecondsIsSentVerbatim 钉住值原样送出，本地不夹。服务端自己把超上限的
// 夹到 60、把非正整数**忽略**而不是拒绝——契约的理由是「优化参数上的笔误不该
// 让一次本来能成的生成失败」。客户端再夹一次就等于把那份容错撤销掉。
func TestWaitSecondsIsSentVerbatim(t *testing.T) {
	for _, seconds := range []int{0, 5, 60, 3600} {
		server, queries := waitAPI(t, http.StatusAccepted, 0)
		wait := seconds
		if _, err := createWith(t, waitClient(t, server, time.Second, DefaultMaxRetries),
			CreateTaskOptions{WaitSeconds: &wait}); err != nil {
			t.Fatalf("CreateTask with wait=%d: %v", seconds, err)
		}
		want := "/jobs/createTask?wait=" + strconv.Itoa(seconds)
		if got := *queries; len(got) != 1 || got[0] != want {
			t.Errorf("wait=%d produced %v, want %s", seconds, got, want)
		}
	}
}

// TestWaitSecondsIsAbsentWhenUnset 钉住不设时整个参数不出现——和 /jobs、/usage
// 同一条理由：契约拒绝空的查询参数，而"没设"必须表达成"没有这个参数"。
func TestWaitSecondsIsAbsentWhenUnset(t *testing.T) {
	server, queries := waitAPI(t, http.StatusAccepted, 0)
	if _, err := createWith(t, waitClient(t, server, time.Second, DefaultMaxRetries), CreateTaskOptions{}); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if got := *queries; len(got) != 1 || got[0] != "/jobs/createTask" {
		t.Errorf("requests = %v, want a bare /jobs/createTask with no query at all", got)
	}
}

func TestNegativeWaitSecondsIsRejectedLocally(t *testing.T) {
	server, queries := waitAPI(t, http.StatusAccepted, 0)
	negative := -1
	if _, err := createWith(t, waitClient(t, server, time.Second, DefaultMaxRetries),
		CreateTaskOptions{WaitSeconds: &negative}); err == nil {
		t.Fatal("a negative wait must be refused before it reaches the network")
	}
	if got := *queries; len(got) != 0 {
		t.Errorf("the request went out anyway: %v", got)
	}
}

// TestWaitReturnsTheTerminalRecordOn200 是 wait 付出代价换来的那条路径。
func TestWaitReturnsTheTerminalRecordOn200(t *testing.T) {
	server, _ := waitAPI(t, http.StatusOK, 0)
	wait := 30
	result, err := createWith(t, waitClient(t, server, time.Second, DefaultMaxRetries),
		CreateTaskOptions{WaitSeconds: &wait})
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	if result.Task == nil {
		t.Fatal("a 200 means the task reached a terminal state; Task must carry the record")
	}
	if result.Task.State != StateSucceeded || result.Task.Cost != "0.1200" || !result.Task.Settled {
		t.Errorf("task = %+v", result.Task)
	}
	if assets := result.Task.ReadyAssets(); len(assets) != 1 {
		t.Errorf("the terminal record lost its assets: %+v", assets)
	}
	// 受理回执那几个字段也要从同一份记录里解出来，别只填一半。
	if result.TaskID != "task_1" || result.State != StateSucceeded {
		t.Errorf("result = %+v", result)
	}
	if result.InFlight() {
		t.Error("InFlight() is true on a terminal result")
	}
	// estimatedCost 在任务记录里根本不存在（那边叫 cost），所以它必然是空的。
	// 这条钉住的是「空不是 bug，是契约」——真正的数字在 Task.Cost 上，
	// 文档里写明了，不能让人以为报价丢了。
	if result.EstimatedCost != "" {
		t.Errorf("EstimatedCost = %q; a finished task reports a real cost, not an estimate",
			result.EstimatedCost)
	}
}

// TestWaitFallsBackToAcceptanceOn202 是最容易写错的那条：**带了 wait 不等于
// 一定拿到终态**。预算用完就退回普通的 202 受理回执，任务还在跑。
func TestWaitFallsBackToAcceptanceOn202(t *testing.T) {
	server, _ := waitAPI(t, http.StatusAccepted, 0)
	wait := 1
	result, err := createWith(t, waitClient(t, server, time.Second, DefaultMaxRetries),
		CreateTaskOptions{WaitSeconds: &wait})
	if err != nil {
		t.Fatalf("a wait that runs out is the ordinary outcome, not an error: %v", err)
	}

	if result.Task != nil {
		t.Fatal("a 202 means the wait ran out; Task must stay nil so the caller cannot " +
			"mistake an in-flight task for a finished one")
	}
	if result.TaskID != "task_1" || result.State != StateQueued {
		t.Errorf("result = %+v", result)
	}
	if result.EstimatedCost != "0.1200" {
		t.Errorf("EstimatedCost = %q, want the held estimate on the 202 path", result.EstimatedCost)
	}
	if !result.InFlight() {
		t.Error("InFlight() is false on a queued result")
	}
}

// TestWaitLiftsThisRequestsOwnDeadline 是这个参数能不能用的前提。
//
// 没有它，wait 超过 RequestTimeout（默认 30 秒，而服务端上限 60）必然在**我们
// 自己**手里超时，然后因为 replayable 再重试三次。实测（刻度压小后）会退化成
// 4 次请求、3.9 秒，最后报 "context deadline exceeded" ——那句话指向网络，
// 而真相是这个客户端挂断了一个本来要到的响应。
func TestWaitLiftsThisRequestsOwnDeadline(t *testing.T) {
	// 服务端握 200ms，而普通请求预算只有 50ms —— 没有抬升就必然自己超时。
	server, queries := waitAPI(t, http.StatusOK, 200*time.Millisecond)
	wait := 1
	result, err := createWith(t, waitClient(t, server, 50*time.Millisecond, DefaultMaxRetries),
		CreateTaskOptions{WaitSeconds: &wait})
	if err != nil {
		t.Fatalf("the wait budget did not lift this request's deadline: %v", err)
	}
	if result.Task == nil {
		t.Fatal("the held-open response did not arrive")
	}
	if got := *queries; len(got) != 1 {
		t.Errorf("the request was retried %d times; a deliberate hold is not a fault", len(got))
	}
}

// TestWaitDoesNotChangeTheOrdinaryRequestDeadline 是上一条的反面：抬升只对这
// 一发生效，别把调用方设的 RequestTimeout 全局放大了。
func TestWaitDoesNotChangeTheOrdinaryRequestDeadline(t *testing.T) {
	server, _ := waitAPI(t, http.StatusAccepted, 200*time.Millisecond)
	client := waitClient(t, server, 50*time.Millisecond, -1)

	wait := 1
	if _, err := createWith(t, client, CreateTaskOptions{WaitSeconds: &wait}); err != nil {
		t.Fatalf("the waiting call should still succeed: %v", err)
	}
	// 同一个 client 上不带 wait 的调用仍然按 50ms 超时。
	if _, err := createWith(t, client, CreateTaskOptions{}); err == nil {
		t.Error("a call without WaitSeconds kept the lifted deadline; the override must " +
			"be scoped to the one request that asked for it")
	}
}

// TestWaitKeepsTaskNilWhenA200CarriesAnInFlightRecord 守住 Task 那句承诺。
//
// 契约说 200 必然是终态，所以这条路径本该走不到。它在这里是因为 Task 对外的
// 意思是"完整的终态记录"，而调用方正是靠它判断还要不要轮询：让一条 queued 的
// 记录挂上去，就是把在途任务当成品交出去。多留一个 nil 只让人多轮一次。
func TestWaitKeepsTaskNilWhenA200CarriesAnInFlightRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":200,"msg":"success","request_id":"r","data":{
			"taskId":"task_1","model":"m","state":"running","cost":"0.1200",
			"createdAt":"2026-09-20T10:00:00Z"}}`))
	}))
	t.Cleanup(server.Close)

	wait := 30
	result, err := createWith(t, waitClient(t, server, time.Second, DefaultMaxRetries),
		CreateTaskOptions{WaitSeconds: &wait})
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if result.Task != nil {
		t.Errorf("a still-running record was published as a terminal one: %+v", result.Task)
	}
	if !result.InFlight() {
		t.Error("InFlight() must still report the task as running")
	}
}
