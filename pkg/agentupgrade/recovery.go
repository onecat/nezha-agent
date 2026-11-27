package agentupgrade

import (
 "errors"
 "fmt"
 "time"
)

// RecoveryAction describes the only safe next step after loading a durable
// transaction snapshot. It never starts installation or marks health success.
type RecoveryAction string

const (
 RecoveryNone RecoveryAction = "none"
 RecoveryAbort RecoveryAction = "abort"
 RecoveryResumeTransfer RecoveryAction = "resume_transfer"
 RecoveryRequireRollback RecoveryAction = "require_rollback"
)

// RecoveryDecision validates an untrusted or corrupted persisted snapshot
// before a scheduler or local supervisor uses it. A crashed install is never
// silently retried, and a health-check state is never considered success.
func RecoveryDecision(t Transaction, now time.Time) (RecoveryAction,error) {
 if now.IsZero() || t.ID=="" || t.ServerID==0 ||
  !digestPattern.MatchString(t.PackageSHA256) ||
  !versionPattern.MatchString(t.Version) || t.ReleaseSequence==0 ||
  t.ExpiresAt.IsZero() {
  return "",errors.New("invalid durable upgrade snapshot")
 }
 switch t.State {
 case StatePending, StateTransferring, StateVerified:
  if !now.Before(t.ExpiresAt) { return RecoveryAbort,nil }
  if t.State==StateTransferring { return RecoveryResumeTransfer,nil }
  return RecoveryNone,nil
 case StateInstalling,StateHealthCheck,StateRollingBack:
  return RecoveryRequireRollback,nil
 case StateSucceeded,StateRolledBack,StateFailed:
  return RecoveryNone,nil
 default:
  return "",fmt.Errorf("unknown durable upgrade state %q",t.State)
 }
}

// ValidateActiveTransactions prevents two concurrent upgrades for the same
// Agent or a reused transaction ID, including after process restart.
// Call under the same database transaction/lock as state persistence.
func ValidateActiveTransactions(items []Transaction, now time.Time) error {
 seenID:=make(map[string]struct{},len(items))
 activeServer:=make(map[uint64]string)
 for _,t:=range items {
  action,err:=RecoveryDecision(t,now)
  if err!=nil { return err }
  _=action
  if _,exists:=seenID[t.ID];exists { return errors.New("duplicate upgrade transaction ID") }
  seenID[t.ID]=struct{}{}
  switch t.State {
  case StateSucceeded,StateRolledBack,StateFailed:
   continue
  }
  if other,exists:=activeServer[t.ServerID];exists {
   return fmt.Errorf("multiple active upgrades for server %d (%s, %s)",t.ServerID,other,t.ID)
  }
  activeServer[t.ServerID]=t.ID
 }
 return nil
}
