package agentupgrade

import (
 "errors"
 "time"
)

// State is the durable transaction state shared by the Dashboard scheduler and
// Agent supervisor. The state machine performs validation only; persistence,
// authorization, identity binding and installation must be implemented separately.
type State string

const (
 StatePending State = "pending"
 StateTransferring State = "transferring"
 StateVerified State = "verified"
 StateInstalling State = "installing"
 StateHealthCheck State = "health_check"
 StateSucceeded State = "succeeded"
 StateRollingBack State = "rolling_back"
 StateRolledBack State = "rolled_back"
 StateFailed State = "failed"
)

type Transaction struct {
 ID string
 ServerID uint64
 PackageSHA256 string
 Version string
 ReleaseSequence uint64
 State State
 ExpiresAt time.Time
}

// Transition rejects illegal state changes, late commands and identity/package
// substitutions. The caller MUST durably persist a new state before side effects.
// In particular, a success receipt is not sufficient without Agent health proof.
func (t Transaction) Transition(next State, now time.Time) (Transaction,error) {
 if t.ID=="" || t.ServerID==0 || !digestPattern.MatchString(t.PackageSHA256) ||
 t.ReleaseSequence==0 || !versionPattern.MatchString(t.Version) || t.ExpiresAt.IsZero() {
  return t,errors.New("invalid transaction identity")
 }
 if now.IsZero() { return t,errors.New("missing transaction time") }
 allowed:=map[State][]State{
  StatePending:{StateTransferring,StateFailed},
  StateTransferring:{StateVerified,StateFailed},
  StateVerified:{StateInstalling,StateFailed},
  StateInstalling:{StateHealthCheck,StateRollingBack},
  StateHealthCheck:{StateSucceeded,StateRollingBack},
  StateRollingBack:{StateRolledBack,StateFailed},
 }
 valid:=false
 for _,s:=range allowed[t.State] { if s==next {valid=true;break} }
 if !valid { return t,errors.New("illegal upgrade state transition") }
 // Expiration prevents starting new operations; a rollback must remain
 // possible even after the task deadline has passed.
 if !now.Before(t.ExpiresAt) && next!=StateRollingBack && next!=StateRolledBack && next!=StateFailed {
  return t,errors.New("upgrade transaction expired")
 }
 t.State=next
 return t,nil
}

// SameIdentity must be checked on every stream, receipt and resumed operation.
func (t Transaction) SameIdentity(other Transaction) bool {
 return t.ID!="" && t.ID==other.ID && t.ServerID!=0 && t.ServerID==other.ServerID &&
 t.PackageSHA256!="" && t.PackageSHA256==other.PackageSHA256 &&
 t.Version==other.Version && t.ReleaseSequence!=0 && t.ReleaseSequence==other.ReleaseSequence
}
