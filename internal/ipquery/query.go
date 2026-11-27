// Package ipquery discovers public addresses using explicitly selected HTTPS
// endpoints. It never transmits Dashboard authentication metadata.
package ipquery

import (
 "context"
 "crypto/tls"
 "errors"
 "io"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "strings"
 "time"
)

type Config struct {
 Enabled bool
 IPv4 bool
 IPv6 bool
 Endpoints []string
}

func DefaultConfig() Config {
 return Config{Enabled:true,IPv4:true,IPv6:true,Endpoints:[]string{
  "https://blog.cloudflare.com/cdn-cgi/trace",
  "https://dash.cloudflare.com/cdn-cgi/trace",
  "https://developers.cloudflare.com/cdn-cgi/trace",
 }}
}

type Query struct {
 cfg Config
 v4,v6 *http.Client
}

func New(cfg Config)(*Query,error){
 if !cfg.Enabled { return &Query{},nil }
 if !cfg.IPv4 && !cfg.IPv6 { return nil,errors.New("no IP family enabled") }
 if len(cfg.Endpoints)<1 || len(cfg.Endpoints)>8 { return nil,errors.New("invalid IP endpoint count") }
 for _,raw:=range cfg.Endpoints {
  u,err:=url.Parse(raw)
  if err!=nil || len(raw)>2048 || u.Scheme!="https" || u.Hostname()=="" || u.User!=nil || u.Fragment!="" {
   return nil,errors.New("IP endpoint must be HTTPS without userinfo or fragment")
  }
 }
 cfg.Endpoints=append([]string(nil),cfg.Endpoints...)
 return &Query{cfg:cfg,v4:client("tcp4"),v6:client("tcp6")},nil
}

func client(network string)*http.Client {
 d:=&net.Dialer{Timeout:3*time.Second}
 return &http.Client{
  Timeout:5*time.Second,
  CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
  Transport:&http.Transport{
   Proxy:nil,
   DialContext:func(ctx context.Context,_ string,addr string)(net.Conn,error){return d.DialContext(ctx,network,addr)},
   TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
   TLSHandshakeTimeout:3*time.Second,
   ResponseHeaderTimeout:3*time.Second,
   DisableKeepAlives:true,
   MaxResponseHeaderBytes:16*1024,
  },
 }
}

func public(a netip.Addr)bool {
 if !a.IsValid() || a.Zone()!="" || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() {return false}
 for _,p:=range []string{"100.64.0.0/10","192.0.0.0/24","192.0.2.0/24","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","240.0.0.0/4","2001:db8::/32","2001:2::/48","2001:10::/28","2001:20::/28"}{
  if netip.MustParsePrefix(p).Contains(a){return false}
 }
 return true
}

func parse(body string,v6 bool)(string,error){
 value:=strings.TrimSpace(body)
 if strings.Contains(value,"\n") || strings.HasPrefix(value,"ip=") {
  value=""
  for _,line:=range strings.Split(body,"\n"){
   if strings.HasPrefix(line,"ip="){
    if value!="" {return "",errors.New("duplicate IP response")}
    value=strings.TrimSpace(strings.TrimPrefix(line,"ip="))
    if value=="" {return "",errors.New("empty IP response")}
   }
  }
 }
 a,err:=netip.ParseAddr(value)
 if err!=nil || !public(a) || a.Is6()!=v6 {return "",errors.New("invalid public IP response")}
 return a.String(),nil
}

func fetch(ctx context.Context,c *http.Client,endpoint string,v6 bool)(string,error){
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil)
 if err!=nil {return "",err}
 resp,err:=c.Do(req)
 if err!=nil {return "",err}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{return "",errors.New("IP endpoint rejected request")}
 b,err:=io.ReadAll(io.LimitReader(resp.Body,8193))
 if err!=nil || len(b)>8192{return "",errors.New("invalid IP response size")}
 return parse(string(b),v6)
}
func(q *Query) family(ctx context.Context,v6 bool)string{
 c:=q.v4
 if v6 {c=q.v6}
 for _,u:=range q.cfg.Endpoints{
  if ctx.Err()!=nil {break}
  if ip,err:=fetch(ctx,c,u,v6);err==nil{return ip}
 }
 return ""
}

// Lookup uses a common deadline for both address families. A disabled query
// makes no network request. Partial success is allowed; failed families are
// never invented or copied from the other family.
func(q *Query) Lookup(ctx context.Context)(string,error){
 if !q.cfg.Enabled{return "",nil}
 ctx,cancel:=context.WithTimeout(ctx,8*time.Second)
 defer cancel()
 type result struct{v6 bool;ip string}
 out:=make(chan result,2)
 n:=0
 if q.cfg.IPv4{n++;go func(){out<-result{false,q.family(ctx,false)}}()}
 if q.cfg.IPv6{n++;go func(){out<-result{true,q.family(ctx,true)}}()}
 var v4,v6 string
 for i:=0;i<n;i++{
  r:=<-out
  if r.v6{v6=r.ip}else{v4=r.ip}
 }
 if v4!="" && v6!="" {return v4+"/"+v6,nil}
 if v4!="" {return v4,nil}
 if v6!="" {return v6,nil}
 return "",errors.New("public IP query unavailable")
}
