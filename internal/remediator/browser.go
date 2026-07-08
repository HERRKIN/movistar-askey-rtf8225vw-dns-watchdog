package remediator

import (
	"context"
	"os"

	"github.com/chromedp/chromedp"
)

// loginDebug reports whether verbose remediation diagnostics are enabled via
// the DEBUG_LOGIN env var. Diagnostics never print the password.
func loginDebug() bool { return os.Getenv("DEBUG_LOGIN") != "" }

// headful reports whether the browser should run with a visible window
// (HEADFUL=1), for local debugging. The default is headless, which is what
// production (and CI) always uses.
func headful() bool { return os.Getenv("HEADFUL") == "1" }

// newBrowserContext builds a chromedp context bound to a real Chrome/Chromium
// process. It supports two env overrides:
//
//   - CHROME_PATH — an explicit path (or PATH-resolvable name) to the browser
//     binary. When unset, chromedp's default allocator searches common
//     locations for Google Chrome / Chromium.
//   - HEADFUL=1 — runs with a visible window instead of headless, useful for
//     watching the flow while debugging against the real router.
//
// The returned cancel function MUST be called (via defer) by the caller to
// release the allocator and browser process; Restore always does this even
// on error paths.
func newBrowserContext(parent context.Context) (context.Context, context.CancelFunc) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)

	// The router admin UI is our own trusted LAN target, not third-party
	// content, and containers commonly run this process as root (see
	// Dockerfile), where Chrome refuses to start its own sandbox. Disabling
	// the sandbox here is a deliberate, scoped tradeoff for that reason.
	opts = append(opts, chromedp.NoSandbox)

	// Flags required to start Chromium reliably inside a container:
	//   - disable-dev-shm-usage: containers give /dev/shm only 64MB by
	//     default, which makes Chromium crash on startup ("chrome failed to
	//     start"); this uses /tmp instead.
	//   - disable-gpu / disable-setuid-sandbox: no GPU or setuid helper in a
	//     headless container.
	// They are harmless for local (headful) debugging too.
	opts = append(opts,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-setuid-sandbox", true),
	)

	if headful() {
		opts = append(opts, chromedp.Flag("headless", false))
	}
	if chromePath := os.Getenv("CHROME_PATH"); chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, opts...)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)

	return ctx, func() {
		cancelCtx()
		cancelAlloc()
	}
}
