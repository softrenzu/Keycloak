package security

import (
  "crypto/ed25519"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "encoding/json"
  "errors"
  "strings"
  "time"
)

var b64 = base64.RawURLEncoding

type Signer struct { Public ed25519.PublicKey; private ed25519.PrivateKey; KID string }
func NewSigner()*Signer{pub,priv,_:=ed25519.GenerateKey(rand.Reader);sum:=sha256.Sum256(pub);return &Signer{Public:pub,private:priv,KID:b64.EncodeToString(sum[:8])}}
func (s *Signer) Sign(claims map[string]any)(string,error){h,_:=json.Marshal(map[string]any{"alg":"EdDSA","typ":"JWT","kid":s.KID});p,_:=json.Marshal(claims);input:=b64.EncodeToString(h)+"."+b64.EncodeToString(p);sig:=ed25519.Sign(s.private,[]byte(input));return input+"."+b64.EncodeToString(sig),nil}
func (s *Signer) Verify(token string)(map[string]any,error){p:=strings.Split(token,".");if len(p)!=3{return nil,errors.New("malformed token")};sig,err:=b64.DecodeString(p[2]);if err!=nil||!ed25519.Verify(s.Public,[]byte(p[0]+"."+p[1]),sig){return nil,errors.New("invalid signature")};raw,err:=b64.DecodeString(p[1]);if err!=nil{return nil,err};var c map[string]any;if err=json.Unmarshal(raw,&c);err!=nil{return nil,err};if exp,ok:=c["exp"].(float64);ok&&time.Now().Unix()>=int64(exp){return nil,errors.New("expired")};return c,nil}
func (s *Signer) JWKS()map[string]any{return map[string]any{"keys":[]any{map[string]any{"kty":"OKP","crv":"Ed25519","x":b64.EncodeToString(s.Public),"use":"sig","alg":"EdDSA","kid":s.KID}}}}
func S256(v string)string{h:=sha256.Sum256([]byte(v));return b64.EncodeToString(h[:])}
