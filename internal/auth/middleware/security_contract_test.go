package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubeseal-ui/api/internal/auth/oidc"
)

func TestRequireCSRFSameTokenRequiresTrustedOrigin(t *testing.T) {
	cfg := DefaultAuthConfig(nil)
	for _, tc := range []struct {
		name   string
		origin string
		want   bool
	}{
		{"trusted", "https://app.example.com", true},
		{"missing", "", false},
		{"untrusted", "https://evil.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-CSRF-Token", "csrf")
			r.AddCookie(&http.Cookie{Name: oidc.CookieCSRF, Value: "csrf"})
			if got := RequireCSRF(httptest.NewRecorder(), r, cfg); got != tc.want {
				t.Fatalf("RequireCSRF() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClearAuthCookiesUsesOriginalPathsAndCSRFIsReadable(t *testing.T) {
	cfg := DefaultAuthConfig(nil)
	rr := httptest.NewRecorder()
	clearAuthCookies(rr, cfg)
	cookies := rr.Result().Cookies()
	if len(cookies) != 4 {
		t.Fatalf("got %d clearing cookies, want 4", len(cookies))
	}
	want := map[string]struct {
		path     string
		httpOnly bool
	}{
		oidc.CookieSession: {"/", true},
		oidc.CookieRefresh: {"/api/v1", true},
		oidc.CookieCSRF:    {"/", false},
		oidc.CookiePKCE:    {"/api/v1/auth/callback", true},
	}
	for _, cookie := range cookies {
		expected, ok := want[cookie.Name]
		if !ok {
			t.Fatalf("unexpected cookie %q", cookie.Name)
		}
		if cookie.Path != expected.path || cookie.HttpOnly != expected.httpOnly {
			t.Errorf("%s: path=%q httpOnly=%v, want path=%q httpOnly=%v", cookie.Name, cookie.Path, cookie.HttpOnly, expected.path, expected.httpOnly)
		}
	}
}
