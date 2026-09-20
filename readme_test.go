package spicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// README 是这个包的首屏。它里面的 Go 代码不是插图，是绝大多数人写下的第一段
// 调用——他们会整段复制走。
//
// 在这条检查之前，没有任何东西编译过它，而它当时**编译不过**：`spicy.TaskRequest`
// 这个类型不存在（真名 CreateTaskInput），`NewIdempotencyKey()` 回两个值被当成
// 一个用，`CreateTask` 少一个参数，`WaitForTerminal` 少一个参数。五个错误。
//
// 这类失效没有信号：README 照常渲染，CI 照常全绿，只有真去复制它的人会撞上，
// 而他撞上的时刻正好是他对这个 SDK 的第一印象。改签名的人也收不到提醒——
// 编译器看不见 Markdown。
//
// 这条做成 *_test.go 而不是 scripts/ 下的独立程序，是因为这个仓库的 CI 只跑
// gofmt / go vet / go test 三条命令（.github/workflows/ci.yml）。放进 scripts/
// 的东西没有任何东西会去执行它，那等于把一条检查写下来然后关掉。

// readmeSnippet 是 README 里一个 Go 代码块的编译上下文。
type readmeSnippet struct {
	// name 出现在失败信息里。
	name string
	// anchor 是这个块里独有的一小段文字。它把表里的这一项和 README 里的那一块
	// 绑定起来：有人调换了块的顺序、或者在中间插了一块，这条检查会当场说清楚
	// 是哪一块对不上，而不是默默地拿错误的上下文去编译错误的代码。
	anchor string
	// prelude 补上这个片段假定"上文已经有了"的东西。README 是连着读的，
	// 后一节接着前一节的变量往下写；把那些变量在这里显式列出来，比让每个
	// 片段都从头建一遍客户端更接近读者真实的复制行为。
	prelude string
	// sink 消化片段自己没有再用到的变量。Go 里"声明了没用"是编译错误，而文档
	// 片段本来就可以只演示到某一步为止。
	sink string
}

// readmeSnippets 逐条登记 README 里的 Go 代码块，顺序与它们在文件里出现的顺序
// 一致。**数量写死在这张表里**：新加一块而不登记，这条检查就会红，而不是静默地
// 漏检那一块。
var readmeSnippets = []readmeSnippet{
	{
		name:   "Generate something",
		anchor: "client.WaitForTerminal",
	},
	{
		name:   "Skipping the first poll",
		anchor: "WaitSeconds: &seconds",
		// request 与 key 由上一块建立，这里只演示 wait 本身。
		prelude: "request := spicy.CreateTaskInput{Model: \"m\", Input: map[string]any{\"prompt\": \"p\"}}\n" +
			"key, _ := spicy.NewIdempotencyKey()\n",
	},
	{
		name:   "Start from a local file",
		anchor: "client.UploadFile",
		sink:   "_, _ = uploaded, err",
	},
	{
		name:   "Balance, usage and history",
		anchor: "client.EachTask",
	},
	{
		name:   "Errors",
		anchor: "var apiErr *spicy.APIError",
	},
}

var readmeGoFence = regexp.MustCompile("(?ms)^```go[^\n]*\n(.*?)^```$")

// snippetHarness 给片段一个能编译的躯壳。
//
// README 里的代码是函数体的一段，不是完整程序，所以它需要一个上下文。片段放在
// 内层 { } 里，`client, err := spicy.New(...)` 这种短声明才能照原样成立——否则
// 它和外层同名的参数撞在同一个作用域里，编译器会说"= 左边没有新变量"，而那是
// 这个躯壳的问题，不是 README 的问题。
//
// 参数可以不被使用，所以只演示到一半的片段不会因为缺上下文而红。
const snippetHarness = `package main

import (
	"context"
	"errors"
	"log"

	spicy "github.com/SpicyAPI/spicy-go"
)

// 片段用不到的 import 在这里消化掉：否则"未使用的 import"会盖过我们真正想看见的
// 类型错误。
var (
	_ = context.Background
	_ = errors.As
	_ = log.Println
	_ = spicy.APIBaseURL
)

func snippet(ctx context.Context, client *spicy.Client, err error) error {
	{
%s
%s
%s
	}
	return nil
}

func main() { _ = snippet }
`

// TestREADMEGoBlocksCompile 编译 README 里的每一个 Go 代码块。
func TestREADMEGoBlocksCompile(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no Go toolchain on PATH; this check needs one to compile the README")
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("locate the repository: %v", err)
	}

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}

	matches := readmeGoFence.FindAllStringSubmatch(string(readme), -1)
	if len(matches) != len(readmeSnippets) {
		t.Fatalf("README.md has %d Go code block(s) but readmeSnippets declares %d.\n"+
			"every Go block must be registered there, or it goes uncompiled and nothing says so",
			len(matches), len(readmeSnippets))
	}

	for i, match := range matches {
		declared := readmeSnippets[i]
		block := match[1]
		if !strings.Contains(block, declared.anchor) {
			t.Errorf("Go block #%d does not contain the anchor %q declared for %q; "+
				"the blocks and readmeSnippets are out of step",
				i+1, declared.anchor, declared.name)
			continue
		}
		t.Run(declared.name, func(t *testing.T) {
			compileSnippet(t, root, declared.prelude, block, declared.sink)
		})
	}
}

// compileSnippet 在一个一次性模块里编译一个片段，模块用 replace 指回本仓库。
func compileSnippet(t *testing.T, root, prelude, block, sink string) {
	t.Helper()

	dir := t.TempDir()

	write := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("go.mod", "module spicyreadmecheck\n\ngo 1.23\n\n"+
		"require github.com/SpicyAPI/spicy-go v0.0.0\n\n"+
		"replace github.com/SpicyAPI/spicy-go => "+root+"\n")
	write("main.go", sprintfHarness(indent(prelude), indent(block), indent(sink)))

	build := exec.Command("go", "build", "./...")
	build.Dir = dir
	// GOFLAGS=-mod=mod 让它自己补 require；GOPROXY=off 与 GOWORK=off 保证这条
	// 检查不上网、也不被上层某个 go.work 改写模块解析——否则它会在某些机器上
	// 因为与 README 无关的原因失败，而一条爱喊狼来了的检查等于没有检查。
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")

	if output, err := build.CombinedOutput(); err != nil {
		t.Errorf("this README code block does not compile:\n%s\n"+
			"fix the README against the real signatures in client.go — not the other way round",
			strings.TrimSpace(string(output)))
	}
}

func sprintfHarness(prelude, body, sink string) string {
	return strings.Replace(snippetHarness, "%s\n%s\n%s", prelude+"\n"+body+"\n"+sink, 1)
}

// indent 把片段缩进到躯壳里的层级，并且保留空行为真正的空行。
func indent(block string) string {
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			lines[i] = ""
			continue
		}
		lines[i] = "\t\t" + line
	}
	return strings.Join(lines, "\n")
}
