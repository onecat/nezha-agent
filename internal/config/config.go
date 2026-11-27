// Package config loads local-only Agent configuration. No remote edits.
package config

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "os"
 "strings"
 "runtime"
 "time"

 "github.com/onecat/nezha-agent/internal/ipquery"
)

type Config struct {
 Address string
 Secret string
 CAFile string
 Interval time.Duration
 IP ipquery.Config
 PreferIPv6Geo bool
 ExcludedInterfaces []string
}

func Defaults() Config {
 return Config{Interval:5*time.Second,IP:ipquery.DefaultConfig()}
}

func Decode(data []byte)(Config,error){
 cfg:=Defaults()
 if len(data)==0 || len(data)>32*1024 {return Config{},errors.New("invalid configuration size")}
 d:=json.NewDecoder(bytes.NewReader(data))
 token,err:=d.Token()
 if err!=nil || token!=json.Delim('{') {return Config{},errors.New("configuration must be an object")}
 seen:=map[string]bool{}
 for d.More(){
  token,err:=d.Token()
  key,ok:=token.(string)
  if err!=nil || !ok || seen[key] {return Config{},errors.New("invalid or duplicate configuration key")}
  seen[key]=true
  var raw json.RawMessage
  if err:=d.Decode(&raw);err!=nil || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {return Config{},errors.New("invalid configuration value")}
  var dst any
  var seconds int
  switch key {
  case "server":dst=&cfg.Address
  case "client_secret":dst=&cfg.Secret
  case "ca_file":dst=&cfg.CAFile
  case "report_interval_seconds":dst=&seconds
  case "enable_ip_query":dst=&cfg.IP.Enabled
  case "ip_query_ipv4":dst=&cfg.IP.IPv4
  case "ip_query_ipv6":dst=&cfg.IP.IPv6
  case "ip_query_endpoints":dst=&cfg.IP.Endpoints
  case "prefer_ipv6_geo":dst=&cfg.PreferIPv6Geo
  case "exclude_network_interfaces":dst=&cfg.ExcludedInterfaces
  default:return Config{},errors.New("unknown configuration key")
  }
  if err:=json.Unmarshal(raw,dst);err!=nil{return Config{},errors.New("invalid configuration value type")}
  if key=="report_interval_seconds" {
   if seconds<1 || seconds>60{return Config{},errors.New("invalid report interval")}
   cfg.Interval=time.Duration(seconds)*time.Second
  }
 }
 if token,err=d.Token();err!=nil || token!=json.Delim('}') {return Config{},errors.New("invalid configuration ending")}
 if _,err=d.Token();err!=io.EOF{return Config{},errors.New("trailing configuration data")}
 if len(cfg.ExcludedInterfaces)>64{return Config{},errors.New("too many excluded interfaces")}
 unique:=map[string]bool{}
 for _,name:=range cfg.ExcludedInterfaces{if name==""||len(name)>128||strings.TrimSpace(name)!=name||unique[name]{return Config{},errors.New("invalid excluded interface name")};unique[name]=true}
 if cfg.Address=="" || cfg.Secret=="" {return Config{},errors.New("server and client_secret required")}
 if _,err:=ipquery.New(cfg.IP);err!=nil{return Config{},err}
 return cfg,nil
}

// Load requires an operator-controlled local regular file. Unix permissions
// must not grant group/other access; Windows ACLs must be restricted by the
// administrator before launching the Agent.
func Load(path string)(Config,error){
 f,err:=os.Open(path)
 if err!=nil{return Config{},errors.New("cannot open configuration")}
 defer f.Close()
 info,err:=f.Stat()
 if err!=nil || !info.Mode().IsRegular() || info.Size()>32*1024{return Config{},errors.New("invalid configuration file")}
 if runtime.GOOS!="windows" && info.Mode().Perm()&0077!=0{return Config{},errors.New("configuration permissions must be private")}
 b,err:=io.ReadAll(io.LimitReader(f,32*1024+1))
 if err!=nil{return Config{},errors.New("cannot read configuration")}
 return Decode(b)
}
