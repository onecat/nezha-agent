package agentupgrade

import (
 "errors"
 "time"
)

// AuthorizationPolicy is a fail-closed, independently provisioned server-side
// gate. An authenticated Dashboard session alone must never grant upgrade rights.
// The transport layer must authenticate and bind both the operator and Agent.
type AuthorizationPolicy struct {
 Enabled bool
 OperatorCanUpgrade bool
 ServerAllowsUpgrade bool
 AgentSupportsUpgrade bool
 AgentVersion string
 AgentOS string
 AgentArch string
 Now time.Time
}

// AuthorizeUpgrade checks the requested target against a verified, signed
// package and a trusted, durable release high-water mark. The caller MUST
// independently authenticate the operator and Agent and check that the target
// ServerID is in the operator's authorized scope. Never derive these booleans
// from untrusted Agent claims or a user-supplied request.
func (p AuthorizationPolicy) AuthorizeUpgrade(t Transaction, pkg VerifiedPackage, highestSequence uint64) error {
 if !p.Enabled || !p.OperatorCanUpgrade || !p.ServerAllowsUpgrade || !p.AgentSupportsUpgrade {
  return errors.New("managed Agent upgrade disabled or unauthorized")
 }
 if p.Now.IsZero() || t.State!=StatePending || t.ID=="" || t.ServerID==0 ||
  !digestPattern.MatchString(t.PackageSHA256) || t.ExpiresAt.IsZero() ||
  !p.Now.Before(t.ExpiresAt) {
  return errors.New("invalid or expired upgrade task")
 }
 if !t.SameIdentity(Transaction{
  ID:t.ID,ServerID:t.ServerID,PackageSHA256:pkg.PackageSHA256,
  Version:pkg.Manifest.Version,ReleaseSequence:pkg.Manifest.ReleaseSequence,
 }) {
  return errors.New("upgrade task and verified package differ")
 }
 if err:=pkg.Manifest.CheckUpgrade(p.AgentOS,p.AgentArch,p.AgentVersion,highestSequence);err!=nil {
  return err
 }
 return nil
}
