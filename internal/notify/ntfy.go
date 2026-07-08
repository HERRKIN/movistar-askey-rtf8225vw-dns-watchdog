// Package notify sends push notifications via a self-hosted ntfy server.
package notify

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Notifier sends notifications to an ntfy topic.
type Notifier struct {
	BaseURL string
	Topic   string
	Client  *http.Client
}

// New creates a Notifier for the given ntfy server base URL and topic.
func New(baseURL, topic string) *Notifier {
	return &Notifier{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Topic:   topic,
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Send posts a notification with the given title and body to the configured
// ntfy topic.
func (n *Notifier) Send(title, body string) error {
	if n.Client == nil {
		n.Client = &http.Client{Timeout: 10 * time.Second}
	}

	url := fmt.Sprintf("%s/%s", n.BaseURL, n.Topic)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: failed to build request: %w", err)
	}
	req.Header.Set("Title", title)

	resp, err := n.Client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: ntfy returned status %d", resp.StatusCode)
	}

	return nil
}
