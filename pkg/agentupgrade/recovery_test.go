package agentupgrade

import (
 "strings"
 "testing"
 "time"
)

func recoveryFixture() Transaction {
 return Transaction{
  ID:"task-1",ServerID:123,PackageSHA256:strings.Repeat("a",64),
  Version:"v0.30.01",ReleaseSequence:2,State:StatePending,
  ExpiresAt:time.Date(2027,1,1,0,0,0,0,time.UTC),
 }
}

func TestRecoveryDecision(t *testing.T) {
 now:=time.Date(2026,12,1,0,0,0,0,time.UTC)
 tests:=[]struct{state State;want RecoveryAction}{
  {StatePending,RecoveryNone},{StateTransferring,RecoveryResumeTransfer},
  {StateVerified,RecoveryNone},{StateInstalling,RecoveryRequireRollback},
  {StateHealthCheck,RecoveryRequireRollback},
  {StateRollingBack,RecoveryRequireRollback},
  {StateSucceeded,RecoveryNone},{StateRolledBack,RecoveryNone},
  {StateFailed,RecoveryNone},
 }
 for _,tt:=range tests {
  t.Run(string(tt.state),func(t *testing.T){
   item:=recoveryFixture();item.State=tt.state
   got,err:=RecoveryDecision(item,now)
   if err!=nil || got!=tt.want { t.Fatalf("got %q, %v; want %q",got,err,tt.want) }
  })
 }
 item:=recoveryFixture()
 for _,state:=range []State{StatePending,StateTransferring,StateVerified} {
  item.State=state
  got,err:=RecoveryDecision(item,item.ExpiresAt)
  if err!=nil || got!=RecoveryAbort { t.Fatalf("expired %s: %q %v",state,got,err) }
 }
 item.State=StateInstalling
 got,err:=RecoveryDecision(item,item.ExpiresAt.Add(time.Hour))
 if err!=nil || got!=RecoveryRequireRollback { t.Fatalf("expired install: %q %v",got,err) }
 item.State="unknown"
 if _,err:=RecoveryDecision(item,now);err==nil { t.Fatal("unknown state accepted") }
 item=recoveryFixture();item.PackageSHA256="invalid"
 if _,err:=RecoveryDecision(item,now);err==nil { t.Fatal("invalid snapshot accepted") }
}

func TestValidateActiveTransactions(t *testing.T) {
 now:=time.Date(2026,12,1,0,0,0,0,time.UTC)
 a:=recoveryFixture()
 b:=recoveryFixture();b.ID="task-2"
 if err:=ValidateActiveTransactions([]Transaction{a,b},now);err==nil { t.Fatal("concurrent upgrades accepted") }
 b.ServerID=456
 if err:=ValidateActiveTransactions([]Transaction{a,b},now);err!=nil { t.Fatal(err) }
 b.ID=a.ID
 if err:=ValidateActiveTransactions([]Transaction{a,b},now);err==nil { t.Fatal("duplicate ID accepted") }
 b.ID="task-2";b.ServerID=a.ServerID;b.State=StateSucceeded
 if err:=ValidateActiveTransactions([]Transaction{a,b},now);err!=nil { t.Fatal(err) }
 a.State=StateRollingBack
 if err:=ValidateActiveTransactions([]Transaction{a,b},now);err!=nil { t.Fatal(err) }
 b.State=StateFailed;b.PackageSHA256="invalid"
 if err:=ValidateActiveTransactions([]Transaction{a,b},now);err==nil { t.Fatal("corrupt terminal snapshot accepted") }
}
