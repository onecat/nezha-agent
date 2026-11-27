//go:build linux

package worker

import (
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "encoding/pem"
 "math/big"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "sync/atomic"
 "testing"
 "time"

 pb "github.com/onecat/nezha-agent/proto"
 "google.golang.org/grpc"
 "google.golang.org/grpc/credentials"
 "google.golang.org/grpc/metadata"
)

type reporter struct{
 pb.UnimplementedNezhaServiceServer
 hosts,states atomic.Int64
 reject atomic.Bool
}
func authorized(ctx context.Context)bool{
 m,_:=metadata.FromIncomingContext(ctx)
 v:=m.Get("client_secret")
 return len(v)==1&&v[0]=="fixture-secret"
}
func(s *reporter) ReportSystemInfo(ctx context.Context,h *pb.Host)(*pb.Receipt,error){
 ok:=authorized(ctx)&&h.GetVersion()=="v0.30.00"
 if ok{s.hosts.Add(1)}
 return &pb.Receipt{Proced:ok},nil
}
func(s *reporter) ReportSystemState(ctx context.Context,_ *pb.State)(*pb.Receipt,error){
 ok:=authorized(ctx)&&s.hosts.Load()>0&&!s.reject.Load()
 if ok{s.states.Add(1)}
 return &pb.Receipt{Proced:ok},nil
}

func TestRealAgentProcessReadiness(t *testing.T){
 dir:=t.TempDir()
 buildCtx,cancelBuild:=context.WithTimeout(context.Background(),3*time.Minute)
 defer cancelBuild()
 cmd:=exec.CommandContext(buildCtx,"go","build","-mod=mod","-o",filepath.Join(dir,"nezha-agent"),"../../cmd/agent")
 if b,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("build worker: %v %s",err,b)}
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
 if err!=nil{t.Fatal(err)}
 cert:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"fixture"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},BasicConstraintsValid:true,IsCA:true}
 der,err:=x509.CreateCertificate(rand.Reader,cert,cert,&key.PublicKey,key)
 if err!=nil{t.Fatal(err)}
 ca:=filepath.Join(dir,"ca.pem")
 if err:=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
 l,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 defer l.Close()
 server:=grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{der},PrivateKey:key}},MinVersion:tls.VersionTLS12})))
 fixture:=new(reporter)
 pb.RegisterNezhaServiceServer(server,fixture)
 go server.Serve(l)
 defer server.Stop()
 data,err:=json.Marshal(map[string]any{"server":l.Addr().String(),"client_secret":"fixture-secret","ca_file":ca,"enable_ip_query":false,"report_interval_seconds":1})
 if err!=nil{t.Fatal(err)}
 config:=filepath.Join(dir,"agent.json")
 if err:=os.WriteFile(config,data,0600);err!=nil{t.Fatal(err)}
 p,err:=New(dir,config)
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second)
 defer cancel()
 defer func(){c,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();if err:=p.Stop(c);err!=nil{t.Error(err)}}()
 if err:=p.Start(ctx);err!=nil{t.Fatal(err)}
 if err:=p.Healthy(ctx,"v0.30.00");err!=nil{t.Fatal(err)}
 if fixture.hosts.Load()==0||fixture.states.Load()==0{t.Fatal("readiness without accepted reports")}
 if err:=p.Healthy(ctx,"v0.30.01");err==nil{t.Fatal("wrong version accepted")}
 if err:=p.Stop(ctx);err!=nil{t.Fatal(err)}
 fixture.reject.Store(true)
 if err:=p.Start(ctx);err!=nil{t.Fatal(err)}
 denied,stop:=context.WithTimeout(ctx,3*time.Second)
 defer stop()
 if err:=p.Healthy(denied,"v0.30.00");err==nil{t.Fatal("new worker accepted old readiness or rejected receipt")}
 if err:=p.Stop(ctx);err!=nil{t.Fatal(err)}
}
