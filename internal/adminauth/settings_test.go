package adminauth

import "testing"

func TestOriginIdentity(t *testing.T) {
	for _, s := range []string{"https://admin.invalid", "https://127.0.0.1:8443", "https://[::1]:8443", ""} {
		if ValidateOrigin(s) != nil {
			t.Fatal("valid", s)
		}
	}
	for _, s := range []string{"https://admin.invalid:443", "https://admin.invalid:0443", "https://admin.invalid:08443", "http://admin.invalid", "https://admin.invalid/", "https://admin.invalid?", "https://admin.invalid/#x", "https://user@admin.invalid", "https://Admin.invalid", "https://admin.invalid:0", "https://admin.invalid:65536", "https://admin.invalid:"} {
		if ValidateOrigin(s) == nil {
			t.Fatal("invalid", s)
		}
	}
}
