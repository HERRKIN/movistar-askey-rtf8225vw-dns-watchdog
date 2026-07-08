package remediator

import "testing"

func TestRestore_DryRun_DoesNotHitSaveEndpoint(t *testing.T) {
	fr := newFakeRouter(t)

	err := Restore(nil, fr.server.URL, Credentials{Password: "secret"}, "192.168.1.254", true)
	if err != nil {
		t.Fatalf("Restore() dry-run unexpected error: %v", err)
	}

	if fr.loginHits.Load() != 1 {
		t.Errorf("login hits = %d, want 1", fr.loginHits.Load())
	}
	if fr.lanPageHits.Load() != 1 {
		t.Errorf("LAN page hits = %d, want 1", fr.lanPageHits.Load())
	}
	if fr.saveHits.Load() != 0 {
		t.Errorf("save endpoint hits = %d, want 0 (dry-run must not write)", fr.saveHits.Load())
	}
	if fr.logoutHits.Load() != 1 {
		t.Errorf("logout hits = %d, want 1 (dry-run should still close the session)", fr.logoutHits.Load())
	}
	if !fr.sawCookieOnLAN {
		t.Error("LAN page request did not carry the session cookie")
	}
}

func TestRestore_RealRun_HitsSaveEndpoint(t *testing.T) {
	fr := newFakeRouter(t)

	err := Restore(nil, fr.server.URL, Credentials{Password: "secret"}, "192.168.1.254", false)
	if err != nil {
		t.Fatalf("Restore() unexpected error: %v", err)
	}

	if fr.saveHits.Load() != 1 {
		t.Errorf("save endpoint hits = %d, want 1", fr.saveHits.Load())
	}
	if fr.logoutHits.Load() != 1 {
		t.Errorf("logout hits = %d, want 1", fr.logoutHits.Load())
	}
}

func TestRestore_LoginFailurePropagates(t *testing.T) {
	fr := newFakeRouter(t)
	fr.rejectLogin = true

	err := Restore(nil, fr.server.URL, Credentials{Password: "wrong"}, "192.168.1.254", true)
	if err == nil {
		t.Fatal("Restore() expected error when login fails, got nil")
	}
	if fr.saveHits.Load() != 0 {
		t.Errorf("save endpoint hits = %d, want 0", fr.saveHits.Load())
	}
}

func TestRestore_MissingLANFieldsPropagatesError(t *testing.T) {
	fr := newFakeRouter(t)
	fr.lanPageHTML = `<html><body>no fields here, no sessionKey either</body></html>`

	err := Restore(nil, fr.server.URL, Credentials{Password: "secret"}, "192.168.1.254", true)
	if err == nil {
		t.Fatal("Restore() expected error when LAN page is missing fields, got nil")
	}
}
