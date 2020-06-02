package goaliyunoss

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	DefaultDir         = "uploads"  // 上传目录
	DefaultExpires     = 60         // 秒
	DefaultMaxFileSize = 1000 << 20 // 1000M
)

type Configs struct {
	AccessKeyId,
	AccessKeySecret,
	Endpoint,
	Bucket string
}

type Param func(p *Params)

type Params struct {
	Host string
	Extension,
	Dir,
	CallbackUrl string
	Expires     int
	MaxFileSize int

	config  ConfigStruct
	expires int64
	fid     string
	key     string
	destDir string
}

type PolicyToken struct {
	AccessKeyId string `json:"accessid"`
	Host        string `json:"host"`
	Expire      int64  `json:"expire"`
	Signature   string `json:"signature"`
	Policy      string `json:"policy"`
	Directory   string `json:"dir"`
	Callback    string `json:"callback"`
	Key         string `json:"key"`
	Fid         string `json:"fid"`
	Url         string `json:"url"`
}

type ConfigStruct struct {
	Expiration string          `json:"expiration"`
	Conditions [][]interface{} `json:"conditions"`
}

type CallbackParam struct {
	CallbackUrl      string `json:"callbackUrl"`
	CallbackBody     string `json:"callbackBody"`
	CallbackBodyType string `json:"callbackBodyType"`
}

type Service struct {
	c Configs
}

func NewService(id, secret, endpoint, bucket string) *Service {
	return &Service{c: Configs{
		AccessKeyId:     id,
		AccessKeySecret: secret,
		Endpoint:        endpoint,
		Bucket:          bucket,
	}}
}

func newParams(params ...Param) Params {
	p := Params{
		Host:        "",
		Extension:   "",
		Dir:         DefaultDir,
		CallbackUrl: "",
		Expires:     DefaultExpires,
		MaxFileSize: DefaultMaxFileSize,
	}

	for _, v := range params {
		v(&p)
	}

	// host
	p.Host = strings.TrimSpace(p.Host)

	var cnf ConfigStruct

	// 扩展名
	if len(p.Extension) > 0 {
		p.Extension = "." + strings.Trim(p.Extension, ".")
	}

	// 过期时间
	p.expires = time.Now().Unix() + int64(p.Expires)
	cnf.Expiration = time.Unix(p.expires, 0).Format("2006-01-02T15:04:05Z")

	// 前缀
	p.Dir = strings.Trim(p.Dir, "/")
	p.destDir = time.Now().Format("200601") + "/"
	if len(p.Dir) > 0 {
		p.destDir = p.Dir + "/" + p.destDir
	}

	// 文件大小
	cnf.Conditions = append(cnf.Conditions, []interface{}{"content-length-range", 0, p.MaxFileSize})

	// 文件名
	p.fid = uuid.New().String()
	p.key = p.destDir + p.fid[0:2] + "/" + p.fid[2:4] + "/" + p.fid + p.Extension
	cnf.Conditions = append(cnf.Conditions, []interface{}{"eq", "$key", p.key})

	// 其他配置
	p.config = cnf

	return p
}

func Host(h string) Param {
	return func(p *Params) {
		p.Host = h
	}
}

func Extension(e string) Param {
	return func(p *Params) {
		p.Extension = e
	}
}

func Dir(d string) Param {
	return func(p *Params) {
		p.Dir = d
	}
}

func CallbackUrl(c string) Param {
	return func(p *Params) {
		p.CallbackUrl = c
	}
}

func Expires(e int) Param {
	return func(p *Params) {
		p.Expires = e
	}
}

func MaxFileSize(s int) Param {
	return func(p *Params) {
		p.MaxFileSize = s
	}
}

func (s *Service) CallbackHandler(r *http.Request) error {
	// Get PublicKey bytes
	bytePublicKey, err := s.getPublicKey(r)
	if err != nil {
		return err
	}
	// Get Authorization bytes : decode from Base64String
	byteAuthorization, err := s.getAuthorization(r)
	if err != nil {
		return err
	}
	// Get MD5 bytes from Newly Constructed Authorization String.
	byteMD5, err := s.getMD5FromNewAuthString(r)
	if s.verifySignature(bytePublicKey, byteMD5, byteAuthorization) == false {
		return errors.New("invalid signature")
	}
	return nil
}

func (s *Service) GetPolicyToken(params ...Param) (t PolicyToken, err error) {
	return s.getPolicyToken(newParams(params...))
}

func (s *Service) getPolicyToken(p Params) (t PolicyToken, err error) {
	if len(s.c.AccessKeyId) == 0 ||
		len(s.c.AccessKeySecret) == 0 ||
		len(s.c.Endpoint) == 0 ||
		len(s.c.Bucket) == 0 {
		return t, errors.New("invalid config")
	}

	// 计算签名
	var b []byte
	b, err = json.Marshal(p.config)
	if err != nil {
		return
	}
	t.Policy = base64.StdEncoding.EncodeToString(b)
	h := hmac.New(func() hash.Hash { return sha1.New() }, []byte(s.c.AccessKeySecret))
	if _, err = io.WriteString(h, t.Policy); err != nil {
		return
	}
	t.Signature = base64.StdEncoding.EncodeToString(h.Sum(nil))

	// 回调参数
	var cbp CallbackParam
	cbp.CallbackUrl = p.CallbackUrl
	cbp.CallbackBody = "filename=${object}&size=${size}&mimeType=${mimeType}&height=${imageInfo.height}&width=${imageInfo.width}"
	cbp.CallbackBodyType = "application/json"
	cbb, err := json.Marshal(cbp)
	if err != nil {
		return t, err
	}
	t.Callback = base64.StdEncoding.EncodeToString(cbb)

	// Host
	if len(p.Host) == 0 {
		t.Host = "https://" + s.c.Bucket + "." + s.c.Endpoint
	} else {
		t.Host = p.Host
	}

	t.AccessKeyId = s.c.AccessKeyId
	t.Expire = p.expires
	t.Directory = p.destDir
	t.Key = p.key
	t.Fid = p.fid
	t.Url = t.Host + "/" + t.Key

	return
}

func (s *Service) verifySignature(bytePublicKey, byteMd5, authorization []byte) bool {
	pubBlock, _ := pem.Decode(bytePublicKey)
	if pubBlock == nil {
		fmt.Printf("Failed to parse PEM block containing the public key")
		return false
	}
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if (pubInterface == nil) || (err != nil) {
		fmt.Printf("x509.ParsePKIXPublicKey(publicKey) failed : %s \n", err)
		return false
	}
	pub := pubInterface.(*rsa.PublicKey)

	errorVerifyPKCS1v15 := rsa.VerifyPKCS1v15(pub, crypto.MD5, byteMd5, authorization)
	if errorVerifyPKCS1v15 != nil {
		fmt.Printf("\nSignature Verification is Failed : %s \n", errorVerifyPKCS1v15.Error())
		//printByteArray(byteMd5, "AuthMd5(fromNewAuthString)")
		//printByteArray(bytePublicKey, "PublicKeyBase64")
		//printByteArray(authorization, "AuthorizationFromRequest")
		return false
	}
	return true
}

func (s *Service) getMD5FromNewAuthString(r *http.Request) ([]byte, error) {
	var byteMD5 []byte
	// Construct the New Auth String from URI+Query+Body
	bodyContent, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		fmt.Printf("Read Request Body failed : %s \n", err.Error())
		return byteMD5, err
	}
	strCallbackBody := string(bodyContent)
	// fmt.Printf("r.URL.RawPath={%s}, r.URL.Query()={%s}, strCallbackBody={%s}\n", r.URL.RawPath, r.URL.Query(), strCallbackBody)
	strURLPathDecode, errUnescape := unescapePath(r.URL.Path, encodePathSegment) //url.PathUnescape(r.URL.Path) for Golang v1.8.2+
	if errUnescape != nil {
		fmt.Printf("url.PathUnescape failed : URL.Path=%s, error=%s \n", r.URL.Path, errUnescape)
		return byteMD5, errUnescape
	}

	// Generate New Auth String prepare for MD5
	strAuth := ""
	if r.URL.RawQuery == "" {
		strAuth = fmt.Sprintf("%s\n%s", strURLPathDecode, strCallbackBody)
	} else {
		strAuth = fmt.Sprintf("%s?%s\n%s", strURLPathDecode, r.URL.RawQuery, strCallbackBody)
	}
	// fmt.Printf("NewlyConstructedAuthString={%s}\n", strAuth)

	// Generate MD5 from the New Auth String
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(strAuth))
	byteMD5 = md5Ctx.Sum(nil)

	return byteMD5, nil
}

func (s *Service) getAuthorization(r *http.Request) ([]byte, error) {
	var byteAuthorization []byte
	// Get Authorization bytes : decode from Base64String
	strAuthorizationBase64 := r.Header.Get("authorization")
	if strAuthorizationBase64 == "" {
		fmt.Println("Failed to get authorization field from request header. ")
		return byteAuthorization, errors.New("no authorization field in Request header")
	}
	byteAuthorization, _ = base64.StdEncoding.DecodeString(strAuthorizationBase64)
	return byteAuthorization, nil
}

func (s *Service) getPublicKey(r *http.Request) ([]byte, error) {
	var bytePublicKey []byte
	// get PublicKey URL
	publicKeyURLBase64 := r.Header.Get("x-oss-pub-key-url")
	if publicKeyURLBase64 == "" {
		fmt.Println("GetPublicKey from Request header failed :  No x-oss-pub-key-url field. ")
		return bytePublicKey, errors.New("no x-oss-pub-key-url field in Request header ")
	}
	publicKeyURL, _ := base64.StdEncoding.DecodeString(publicKeyURLBase64)
	// fmt.Printf("publicKeyURL={%s}\n", publicKeyURL)
	// get PublicKey Content from URL
	responsePublicKeyURL, err := http.Get(string(publicKeyURL))
	if err != nil {
		fmt.Printf("Get PublicKey Content from URL failed : %s \n", err.Error())
		return bytePublicKey, err
	}
	bytePublicKey, err = ioutil.ReadAll(responsePublicKeyURL.Body)
	if err != nil {
		fmt.Printf("Read PublicKey Content from URL failed : %s \n", err.Error())
		return bytePublicKey, err
	}
	defer responsePublicKeyURL.Body.Close()
	// fmt.Printf("publicKey={%s}\n", bytePublicKey)
	return bytePublicKey, nil
}

// ============================================================================

type encoding int

const (
	encodePath encoding = 1 + iota
	encodePathSegment
	encodeHost
	encodeZone
	encodeUserPassword
	encodeQueryComponent
	encodeFragment
)

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

type EscapeError string

func (e EscapeError) Error() string {
	return "invalid URL escape " + strconv.Quote(string(e))
}

type InvalidHostError string

func (e InvalidHostError) Error() string {
	return "invalid character " + strconv.Quote(string(e)) + " in host name"
}

// unescapePath : unescapes a string; the mode specifies, which section of the URL string is being unescaped.
func unescapePath(s string, mode encoding) (string, error) {
	// Count %, check that they're well-formed.
	mode = encodePathSegment
	n := 0
	hasPlus := false
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			n++
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[:3]
				}
				return "", EscapeError(s)
			}
			// Per https://tools.ietf.org/html/rfc3986#page-21
			// in the host component %-encoding can only be used
			// for non-ASCII bytes.
			// But https://tools.ietf.org/html/rfc6874#section-2
			// introduces %25 being allowed to escape a percent sign
			// in IPv6 scoped-address literals. Yay.
			if mode == encodeHost && unhex(s[i+1]) < 8 && s[i:i+3] != "%25" {
				return "", EscapeError(s[i : i+3])
			}
			if mode == encodeZone {
				// RFC 6874 says basically "anything goes" for zone identifiers
				// and that even non-ASCII can be redundantly escaped,
				// but it seems prudent to restrict %-escaped bytes here to those
				// that are valid host name bytes in their unescaped form.
				// That is, you can use escaping in the zone identifier but not
				// to introduce bytes you couldn't just write directly.
				// But Windows puts spaces here! Yay.
				v := unhex(s[i+1])<<4 | unhex(s[i+2])
				if s[i:i+3] != "%25" && v != ' ' && shouldEscape(v, encodeHost) {
					return "", EscapeError(s[i : i+3])
				}
			}
			i += 3
		case '+':
			hasPlus = mode == encodeQueryComponent
			i++
		default:
			if (mode == encodeHost || mode == encodeZone) && s[i] < 0x80 && shouldEscape(s[i], mode) {
				return "", InvalidHostError(s[i : i+1])
			}
			i++
		}
	}

	if n == 0 && !hasPlus {
		return s, nil
	}

	t := make([]byte, len(s)-2*n)
	j := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			t[j] = unhex(s[i+1])<<4 | unhex(s[i+2])
			j++
			i += 3
		case '+':
			if mode == encodeQueryComponent {
				t[j] = ' '
			} else {
				t[j] = '+'
			}
			j++
			i++
		default:
			t[j] = s[i]
			j++
			i++
		}
	}
	return string(t), nil
}

// Please be informed that for now shouldEscape does not check all
// reserved characters correctly. See golang.org/issue/5684.
func shouldEscape(c byte, mode encoding) bool {
	// §2.3 Unreserved characters (alphanum)
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}

	if mode == encodeHost || mode == encodeZone {
		// §3.2.2 Host allows
		//	sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
		// as part of reg-name.
		// We add : because we include :port as part of host.
		// We add [ ] because we include [ipv6]:port as part of host.
		// We add < > because they're the only characters left that
		// we could possibly allow, and Parse will reject them if we
		// escape them (because hosts can't use %-encoding for
		// ASCII bytes).
		switch c {
		case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '[', ']', '<', '>', '"':
			return false
		}
	}

	switch c {
	case '-', '_', '.', '~': // §2.3 Unreserved characters (mark)
		return false

	case '$', '&', '+', ',', '/', ':', ';', '=', '?', '@': // §2.2 Reserved characters (reserved)
		// Different sections of the URL allow a few of
		// the reserved characters to appear unescaped.
		switch mode {
		case encodePath: // §3.3
			// The RFC allows : @ & = + $ but saves / ; , for assigning
			// meaning to individual path segments. This package
			// only manipulates the path as a whole, so we allow those
			// last three as well. That leaves only ? to escape.
			return c == '?'

		case encodePathSegment: // §3.3
			// The RFC allows : @ & = + $ but saves / ; , for assigning
			// meaning to individual path segments.
			return c == '/' || c == ';' || c == ',' || c == '?'

		case encodeUserPassword: // §3.2.1
			// The RFC allows ';', ':', '&', '=', '+', '$', and ',' in
			// userinfo, so we must escape only '@', '/', and '?'.
			// The parsing of userinfo treats ':' as special so we must escape
			// that too.
			return c == '@' || c == '/' || c == '?' || c == ':'

		case encodeQueryComponent: // §3.4
			// The RFC reserves (so we must escape) everything.
			return true

		case encodeFragment: // §4.1
			// The RFC text is silent but the grammar allows
			// everything, so escape nothing.
			return false
		}
	}

	// Everything else must be escaped.
	return true
}
