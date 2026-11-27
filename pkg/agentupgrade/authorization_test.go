package agentupgrade

import (
 "strings"
 "testing"
 "time"
)

func TestAuthorizeUpgradeFailClosed(t *testing.T) {
 now:=time.Date(2026,11,26,0,0,0,0,time.UTC)
 m:=Manifest{FormatVersion:1,Component:"nezha-agent",ProtocolVersion:ProtocolVersion,Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:"amd64",Filename:"nezha-agent",Size:10,SHA256:strings.Repeat("a",64),SigningKeyID:"release",ReleaseSequence:3}
 pkg:=VerifiedPackage{Manifest:m,PackageSHA256:strings.Repeat("b",64)}
 tx:=Transaction{ID:"task-1",ServerID:7,PackageSHA256:pkg.PackageSHA256,Version:m.Version,ReleaseSequence:m.ReleaseSequence,State:StatePending,ExpiresAt:now.Add(time.Hour)}
 policy:=AuthorizationPolicy{Enabled:true,OperatorCanUpgrade:true,ServerAllowsUpgrade:true,AgentSupportsUpgrade:true,AgentVersion:"v0.30.00",AgentOS:"linux",AgentArch:"amd64",Now:now}
 if err:=policy.AuthorizeUpgrade(tx,pkg,2);err!=nil {t.Fatal(err)}
 cases:=[]struct{name string; mutate func(*AuthorizationPolicy,*Transaction,*VerifiedPackage); high uint64}{
  {"disabled",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.Enabled=false},2},
  {"operator denied",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.OperatorCanUpgrade=false},2},
  {"server denied",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.ServerAllowsUpgrade=false},2},
  {"legacy agent",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.AgentSupportsUpgrade=false;p.AgentVersion="v0.20.5"},2},
  {"wrong platform",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.AgentArch="arm64"},2},
  {"stale sequence",func(_ *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){},3},
  {"task expired",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.Now=p.Now.Add(time.Hour)},2},
  {"wrong digest",func(_ *AuthorizationPolicy,t *Transaction,_ *VerifiedPackage){t.PackageSHA256=strings.Repeat("c",64)},2},
  {"wrong version",func(_ *AuthorizationPolicy,t *Transaction,_ *VerifiedPackage){t.Version="v0.30.02"},2},
  {"wrong release sequence",func(_ *AuthorizationPolicy,t *Transaction,_ *VerifiedPackage){t.ReleaseSequence=4},2},
  {"nonpending task",func(_ *AuthorizationPolicy,t *Transaction,_ *VerifiedPackage){t.State=StateVerified},2},
  {"unsigned invalid manifest",func(_ *AuthorizationPolicy,_ *Transaction,pkg *VerifiedPackage){pkg.Manifest.SigningKeyID=""},2},
  {"missing clock",func(p *AuthorizationPolicy,_ *Transaction,_ *VerifiedPackage){p.Now=time.Time{}},2},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  p,x,v:=policy,tx,pkg
  tc.mutate(&p,&x,&v)
  if err:=p.AuthorizeUpgrade(x,v,tc.high);err==nil {t.Fatal("unauthorized upgrade accepted")}
 })}
}
