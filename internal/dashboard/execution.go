package dashboard

import (
 "context"
 "errors"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 wire "github.com/onecat/nezha-agent/pkg/upgradewire"
)

// RequestInstallGrant is deliberately not retried automatically. A missing
// response is not authority to install. The caller MUST reserve the sequence
// durably before calling and hold exclusive local supervisor ownership.
func(c *Client) RequestInstallGrant(ctx context.Context,d *DownloadedUpgrade)error{
 if d==nil||d.stage==nil||d.owner!=c||d.task.State!=core.StateVerified||!time.Now().Before(d.task.ExpiresAt){return errors.New("invalid local grant request")}
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout)
 defer cancel()
 return wire.Grant(ctx,c.conn,d.task)
}

// ReportUpgradeResult takes a locally persisted terminal transaction, not
// an arbitrary network command or merely a successful download.
func(c *Client) ReportUpgradeResult(ctx context.Context,t core.Transaction)error{
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout)
 defer cancel()
 return wire.Result(ctx,c.conn,t)
}
