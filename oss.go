package goaliyunoss

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"hash"
	"io"
	"net/http"
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
