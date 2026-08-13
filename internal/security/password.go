package security

import (
  "crypto/rand"
  "crypto/sha256"
  "crypto/subtle"
  "encoding/base64"
  "strings"
)

func HashPassword(password string) string {
  salt:=make([]byte,16); _,_=rand.Read(salt)
  sum:=derive([]byte(password),salt,250000)
  return base64.RawURLEncoding.EncodeToString(salt)+"."+base64.RawURLEncoding.EncodeToString(sum)
}
func VerifyPassword(encoded,password string) bool {
  p:=strings.Split(encoded,"."); if len(p)!=2{return false}
  salt,e1:=base64.RawURLEncoding.DecodeString(p[0]); want,e2:=base64.RawURLEncoding.DecodeString(p[1]); if e1!=nil||e2!=nil{return false}
  got:=derive([]byte(password),salt,250000); return subtle.ConstantTimeCompare(got,want)==1
}
func derive(password,salt []byte,rounds int)[]byte{buf:=append(append([]byte{},salt...),password...);sum:=sha256.Sum256(buf);out:=sum[:];for i:=1;i<rounds;i++{x:=sha256.Sum256(append(out,password...));out=x[:]};return out}
