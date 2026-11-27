package dashboard

import (
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "math/big"
 "net"
 "testing"
 "time"

 pb "github.com/onecat/nezha-agent/proto"
 "google.golang.org/grpc"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/credentials"
 "google.golang.org/grpc/metadata"
 "google.golang.org/grpc/status"
)

type testServer struct { pb.UnimplementedNezhaServiceServer }
func auth(ctx context.Context)error {
 m,_:=metadata.FromIncomingContext(ctx)
 v:=m.Get("client_secret")
 if len(v)!=1 || v[0]!="test-secret" { return status.Error(codes.Unauthenticated,"rejected") }
 return nil
}
func (testServer) ReportSystemInfo(ctx context.Context,h *pb.Host)(*pb.Receipt,error) {
 if err:=auth(ctx);err!=nil { return nil,err }
 return &pb.Receipt{Proced:h.GetVersion()=="v0.30.00" && h.GetIp()==""},nil
}
func (testServer) ReportSystemState(ctx context.Context,s *pb.State)(*pb.Receipt,error) {
 if err:=auth(ctx);err!=nil { return nil,err }
 return &pb.Receipt{Proced:s.GetMemUsed()==123 && s.GetGpu()==5},nil
}
func (testServer) RequestTask(h *pb.Host,stream pb.NezhaService_RequestTaskServer)error {
 if err:=auth(stream.Context());err!=nil { return err }
 return stream.Send(&pb.Task{Id:7,Type:11})
}

func startServer(t *testing.T,withTLS bool)(string,*x509.CertPool) {
 t.Helper()
 l,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil { t.Fatal(err) }
 t.Cleanup(func(){l.Close()})
 roots:=x509.NewCertPool()
 var opts []grpc.ServerOption
 if withTLS {
  key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
  if err!=nil { t.Fatal(err) }
  tmpl:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"test"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},IsCA:true,BasicConstraintsValid:true}
  der,err:=x509.CreateCertificate(rand.Reader,tmpl,tmpl,&key.PublicKey,key)
  if err!=nil { t.Fatal(err) }
  cert,err:=x509.ParseCertificate(der)
  if err!=nil { t.Fatal(err) }
  roots.AddCert(cert)
  opts=append(opts,grpc.Creds(credentials.NewTLS(&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{der},PrivateKey:key}},MinVersion:tls.VersionTLS12})))
 }
 srv:=grpc.NewServer(opts...)
 pb.RegisterNezhaServiceServer(srv,testServer{})
 go srv.Serve(l)
 t.Cleanup(srv.Stop)
 return l.Addr().String(),roots
}

func TestAuthenticatedLegacyRPC(t *testing.T){
 addr,roots:=startServer(t,true)
 c,err:=New(Config{Address:addr,Secret:"test-secret",RootCAs:roots})
 if err!=nil { t.Fatal(err) }
 defer c.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
 defer cancel()
 h:=&pb.Host{Version:"v0.30.00"}
 if err:=c.ReportHost(ctx,h);err!=nil { t.Fatal(err) }
 if err:=c.ReportState(ctx,&pb.State{MemUsed:123,Gpu:5});err!=nil { t.Fatal(err) }
 if err:=c.ReportHost(ctx,&pb.Host{});err==nil { t.Fatal("negative receipt accepted") }
 stream,err:=c.RequestTasks(ctx,h)
 if err!=nil { t.Fatal(err) }
 task,err:=stream.Recv()
 if err!=nil || task.GetId()!=7 || task.GetType()!=11 { t.Fatalf("task: %v %v",task,err) }
}

func TestRejectInvalidTransportAndAuthentication(t *testing.T){
 addr,roots:=startServer(t,true)
 plain,_:=startServer(t,false)
 for _,tc:=range []struct{name,addr,secret string; roots *x509.CertPool}{
  {"unknown CA",addr,"test-secret",x509.NewCertPool()},
  {"wrong secret",addr,"incorrect",roots},
  {"plaintext",plain,"test-secret",roots},
 } {
  t.Run(tc.name,func(t *testing.T){
   c,err:=New(Config{Address:tc.addr,Secret:tc.secret,RootCAs:tc.roots})
   if err!=nil { t.Fatal(err) }
   defer c.Close()
   ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
   defer cancel()
   if err:=c.ReportHost(ctx,&pb.Host{Version:"v0.30.00"});err==nil { t.Fatal("invalid connection accepted") }
  })
 }
}

func TestInvalidConfig(t *testing.T){
 for _,a:=range []string{"","https://localhost:443","localhost","localhost:0","localhost:65536","dns:///localhost:443"} {
  if c,err:=New(Config{Address:a,Secret:"test-secret"});err==nil { c.Close();t.Fatalf("accepted %q",a) }
 }
 if c,err:=New(Config{Address:"localhost:443",Secret:"bad\nsecret"});err==nil { c.Close();t.Fatal("accepted malformed secret") }
}
