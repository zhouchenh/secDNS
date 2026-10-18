package server

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/url"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	zxqr "github.com/makiuchi-d/gozxing/qrcode"
	"github.com/zhouchenh/secDNS/internal/adminauth"
)

func TestEnrollmentQRDecodedProfile(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	for _, identity := range []adminauth.Identity{{RealmID: "realm-a", NodeID: "node-a"}, {RealmID: strings.Repeat("r", 64), NodeID: strings.Repeat("n", 64)}} {
		encoded, e := enrollmentPNG(adminauth.Enrollment{Secret: secret}, identity)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			t.Fatal(e)
		}
		img, e := png.Decode(bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		if img.Bounds().Dx() != 320 || img.Bounds().Dy() != 320 {
			t.Fatal("image dimensions")
		}
		bitmap, e := gozxing.NewBinaryBitmapFromImage(img)
		if e != nil {
			t.Fatal(e)
		}
		result, e := zxqr.NewQRCodeReader().Decode(bitmap, nil)
		if e != nil {
			t.Fatal("independent decode", e)
		}
		u, e := url.Parse(result.GetText())
		if e != nil {
			t.Fatal(e)
		}
		if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/secDNS:"+identity.RealmID+"/"+identity.NodeID {
			t.Fatal("identity")
		}
		q := u.Query()
		if len(q) != 5 || q.Get("secret") != secret || q.Get("issuer") != "secDNS" || q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
			t.Fatal("profile")
		}
	}
	for _, secret := range []string{"", strings.Repeat("A", 10000), "jbswy3dpehpk3pxp"} {
		if _, e := enrollmentPNG(adminauth.Enrollment{Secret: secret}, adminauth.Identity{RealmID: "realm-a", NodeID: "node-a"}); e == nil {
			t.Fatal("invalid seed")
		}
	}
}
