package config

import (
 "os"
 "path/filepath"
 "runtime"
 "testing"
 "time"
)

func TestDefaultsAndOffline(t *testing.T){
 c,err:=Decode([]byte(`{"server":"localhost:443","client_secret":"test"}`))
 if err!=nil || !c.IP.Enabled || !c.IP.IPv4 || !c.IP.IPv6 || c.Interval!=5*time.Second {t.Fatal("invalid defaults",err)}
 c,err=Decode([]byte(`{"server":"localhost:443","client_secret":"test","enable_ip_query":false,"report_interval_seconds":10}`))
 if err!=nil || c.IP.Enabled || c.Interval!=10*time.Second{t.Fatal("offline configuration failed",err)}
}
func TestInvalid(t *testing.T){
 for _,s:=range []string{
  `{}`,`{"server":"x","client_secret":"s","client_secret":"other"}`,
  `{"server":"x","client_secret":"s","enable_auto_update":true}`,
  `{"server":"x","client_secret":"s","report_interval_seconds":0}`,
  `{"server":"x","client_secret":null}`,`{"server":"x","client_secret":"s"}{}`,
  `{"server":"x","client_secret":"s","ip_query_endpoints":["http://example.com"]}`,
  `{"server":"x","client_secret":"s","exclude_network_interfaces":["lo","lo"]}`,
  `{"server":"x","client_secret":"s","exclude_network_interfaces":[""]}`,
  `{"server":"x","client_secret":"s","exclude_network_interfaces":null}`,
 }{
  if _,err:=Decode([]byte(s));err==nil{t.Fatal("invalid configuration accepted")}
 }
}
func TestExcludedInterfaces(t *testing.T){
 c,err:=Decode([]byte(`{"server":"localhost:443","client_secret":"test","exclude_network_interfaces":["lo","docker0"]}`))
 if err!=nil||len(c.ExcludedInterfaces)!=2||c.ExcludedInterfaces[0]!="lo"{t.Fatal(c,err)}
}
func TestFilePermissions(t *testing.T){
 p:=filepath.Join(t.TempDir(),"agent.json")
 if err:=os.WriteFile(p,[]byte(`{"server":"localhost:443","client_secret":"test"}`),0600);err!=nil{t.Fatal(err)}
 if _,err:=Load(p);err!=nil{t.Fatal(err)}
 if runtime.GOOS!="windows"{
  if err:=os.Chmod(p,0644);err!=nil{t.Fatal(err)}
  if _,err:=Load(p);err==nil{t.Fatal("accepted public configuration")}
 }
}
