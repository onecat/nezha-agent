package ipquery

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestParse(t *testing.T){
 for _,tc:=range []struct{body string;v6 bool;want string}{
  {"8.8.8.8",false,"8.8.8.8"},{"fl=1\nip=1.1.1.1\n",false,"1.1.1.1"},
  {"ip=2606:4700::1111\n",true,"2606:4700::1111"},
  {"10.0.0.1",false,""},{"100.64.0.1",false,""},{"192.0.2.1",false,""},
  {"127.0.0.1",false,""},{"::1",true,""},{"fe80::1%eth0",true,""},
  {"::ffff:8.8.8.8",true,""},{"8.8.8.8",true,""},{"ip=8.8.8.8\nip=1.1.1.1",false,""},
 }{
  got,err:=parse(tc.body,tc.v6)
  if got!=tc.want || (err==nil)!=(tc.want!=""){t.Fatalf("parse %q: %q %v",tc.body,got,err)}
 }
}

func TestFetch(t *testing.T){
 s:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Header.Get("client_secret")!="" {t.Error("secret leaked")}
  switch r.URL.Path{
  case "/ok":w.Write([]byte("ip=8.8.8.8\n"))
  case "/large":w.Write([]byte(strings.Repeat("x",8193)))
  default:w.WriteHeader(503)
  }
 }))
 defer s.Close()
 if ip,err:=fetch(context.Background(),s.Client(),s.URL+"/ok",false);err!=nil||ip!="8.8.8.8"{t.Fatalf("%q %v",ip,err)}
 for _,path:=range []string{"/large","/error"}{
  if _,err:=fetch(context.Background(),s.Client(),s.URL+path,false);err==nil{t.Fatal("invalid response accepted")}
 }
}

func TestConfig(t *testing.T){
 q,err:=New(Config{})
 if err!=nil{t.Fatal(err)}
 if ip,err:=q.Lookup(context.Background());ip!=""||err!=nil{t.Fatal("disabled query failed")}
 for _,u:=range []string{"http://example.com","https://user@example.com","https://example.com/#x"}{
  if _,err:=New(Config{Enabled:true,IPv4:true,Endpoints:[]string{u}});err==nil{t.Fatal("invalid endpoint accepted")}
 }
 if _,err:=New(DefaultConfig());err!=nil{t.Fatal(err)}
}
