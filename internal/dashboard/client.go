// Package dashboard implements the local v0.30.05 authenticated wire client.
package dashboard

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "net"
 "net/netip"
 "strconv"
 "strings"
 "time"

 pb "github.com/onecat/nezha-agent/proto"
 "google.golang.org/grpc"
 "google.golang.org/grpc/credentials"
)

const rpcTimeout = 10*time.Second

type Config struct {
 // Address is the TLS reverse proxy host:port (not the plaintext backend).
 Address string
 Secret string
 // RootCAs optionally replaces system roots for an internal CA.
 RootCAs *x509.CertPool
}

type secretCredentials struct { secret string }

func (s secretCredentials) GetRequestMetadata(context.Context,...string)(map[string]string,error) {
 return map[string]string{"client_secret":s.secret},nil
}
func (secretCredentials) RequireTransportSecurity() bool { return true }

type Client struct {
 conn *grpc.ClientConn
 rpc pb.NezhaServiceClient
}

func New(cfg Config)(*Client,error) {
 host,port,err:=net.SplitHostPort(cfg.Address)
 if err!=nil || host=="" || strings.ContainsAny(host," /\\?#@%\t\r\n") {
  return nil,errors.New("Dashboard address must be a TLS host:port")
 }
 n,err:=strconv.Atoi(port)
 if err!=nil || n<1 || n>65535 || strconv.Itoa(n)!=port {
  return nil,errors.New("invalid Dashboard port")
 }
 if len(cfg.Secret)==0 || len(cfg.Secret)>1024 { return nil,errors.New("invalid Agent secret") }
 for _,r:=range cfg.Secret { if r<33 || r>126 { return nil,errors.New("invalid Agent secret") } }
 roots:=cfg.RootCAs
 if roots!=nil { roots=roots.Clone() }
 transport:=credentials.NewTLS(&tls.Config{
  MinVersion:tls.VersionTLS12,
  ServerName:host,
  RootCAs:roots,
 })
 // passthrough prevents arbitrary resolver schemes supplied by configuration.
 conn,err:=grpc.NewClient("passthrough:///"+cfg.Address,
  grpc.WithTransportCredentials(transport),
  grpc.WithPerRPCCredentials(secretCredentials{cfg.Secret}),
  grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024),grpc.MaxCallSendMsgSize(1024*1024)),
 )
 if err!=nil { return nil,errors.New("cannot create Dashboard connection") }
 return &Client{conn:conn,rpc:pb.NewNezhaServiceClient(conn)},nil
}

func (c *Client) Close()error { return c.conn.Close() }

func checkReceipt(r *pb.Receipt,err error)error {
 if err!=nil { return err }
 if r==nil || !r.GetProced() { return errors.New("Dashboard rejected report") }
 return nil
}

func (c *Client) ReportHost(ctx context.Context,h *pb.Host)error {
 if h==nil { return errors.New("missing host report") }
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout)
 defer cancel()
 return checkReceipt(c.rpc.ReportSystemInfo(ctx,h))
}
func (c *Client) ReportState(ctx context.Context,s *pb.State)error {
 if s==nil { return errors.New("missing state report") }
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout)
 defer cancel()
 return checkReceipt(c.rpc.ReportSystemState(ctx,s))
}

// RequestTasks establishes the legacy server-streaming RPC. The caller owns
// the context and must cancel it on disconnect. No task is executed here.
func (c *Client) RequestTasks(ctx context.Context,h *pb.Host)(pb.NezhaService_RequestTaskClient,error) {
 if h==nil { return nil,errors.New("missing host report") }
 return c.rpc.RequestTask(ctx,h)
}

 // LookupGeoIP uses the Dashboard's embedded database, not an external service.
func (c *Client) LookupGeoIP(ctx context.Context,ip string)error {
 a,err:=netip.ParseAddr(ip)
 if err!=nil || a.Zone()!="" || a.Is4In6() { return errors.New("invalid GeoIP address") }
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout)
 defer cancel()
 r,err:=c.rpc.LookupGeoIP(ctx,&pb.GeoIP{Ip:a.String()})
 if err!=nil{return err}
 if r==nil || r.GetIp()!=a.String(){return errors.New("invalid GeoIP receipt")}
 return nil
}
