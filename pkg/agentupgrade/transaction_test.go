package agentupgrade

import (
 "strings"
 "testing"
 "time"
)

func TestTransactionTransitions(t *testing.T) {
 now:=time.Unix(1000,0)
 tx:=Transaction{ID:"task-1",ServerID:7,PackageSHA256:strings.Repeat("a",64),Version:"v0.30.01",ReleaseSequence:2,State:StatePending,ExpiresAt:now.Add(time.Hour)}
 for _,next:=range []State{StateTransferring,StateVerified,StateInstalling,StateHealthCheck,StateSucceeded} {
  var err error
  tx,err=tx.Transition(next,now)
  if err!=nil {t.Fatalf("%s: %v",next,err)}
 }
 if _,err:=tx.Transition(StatePending,now);err==nil {t.Fatal("accepted restart of completed transaction")}
 if _,err:=tx.Transition(StateSucceeded,now);err==nil {t.Fatal("accepted duplicate completion")}
 other:=tx
 other.ServerID++
 if tx.SameIdentity(other) {t.Fatal("accepted different server")}
 other=tx
 other.PackageSHA256=strings.Repeat("b",64)
 if tx.SameIdentity(other) {t.Fatal("accepted package substitution")}
 other=tx
 other.ReleaseSequence++
 if tx.SameIdentity(other) {t.Fatal("accepted release substitution")}
 if !tx.SameIdentity(tx) {t.Fatal("rejected same identity")}
}

func TestTransactionRollbackAfterExpiry(t *testing.T) {
 now:=time.Unix(1000,0)
 tx:=Transaction{ID:"task-2",ServerID:9,PackageSHA256:strings.Repeat("a",64),Version:"v0.30.01",ReleaseSequence:3,State:StateInstalling,ExpiresAt:now.Add(-time.Second)}
 if _,err:=tx.Transition(StateHealthCheck,now);err==nil {t.Fatal("accepted expired forward operation")}
 next,err:=tx.Transition(StateRollingBack,now)
 if err!=nil {t.Fatal(err)}
 next,err=next.Transition(StateRolledBack,now)
 if err!=nil {t.Fatal(err)}
 if _,err:=next.Transition(StateInstalling,now);err==nil {t.Fatal("accepted rollback restart")}
}

func TestTransactionNoSkipping(t *testing.T) {
 now:=time.Unix(1000,0)
 tx:=Transaction{ID:"task-3",ServerID:9,PackageSHA256:strings.Repeat("a",64),Version:"v0.30.01",ReleaseSequence:3,State:StatePending,ExpiresAt:now.Add(time.Hour)}
 for _,s:=range []State{StateVerified,StateInstalling,StateHealthCheck,StateSucceeded,StateRollingBack,StateRolledBack} {
  if _,err:=tx.Transition(s,now);err==nil {t.Fatalf("accepted skipped transition %s",s)}
 }
 tx.ID=""
 if _,err:=tx.Transition(StateTransferring,now);err==nil {t.Fatal("accepted missing identity")}
}
