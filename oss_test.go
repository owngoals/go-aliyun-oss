package goaliyunoss

import "testing"

func TestService_GetPolicyToken(t *testing.T) {
	id := ""
	secret := ""
	endpoint := ""
	bucket := ""
	s := NewService(id, secret, endpoint, bucket)
	token, err := s.GetPolicyToken(
		Host("https://cdn.example.com"),
		Extension("png"),
		Dir("gooss"),
		CallbackUrl("http://localhost:1234/callback/aliyunoss"),
		Expires(120),
		MaxFileSize(10<<20),
	)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	t.Logf("token: %+v", token)
}
