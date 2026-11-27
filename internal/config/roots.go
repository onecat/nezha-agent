package config
import("crypto/x509";"errors";"io";"os")
func Roots(path string)(*x509.CertPool,error){
 if path=="" {return nil,nil}
 f,err:=os.Open(path)
 if err!=nil{return nil,errors.New("cannot open CA file")}
 defer f.Close()
 info,err:=f.Stat()
 if err!=nil || !info.Mode().IsRegular(){return nil,errors.New("invalid CA file")}
 b,err:=io.ReadAll(io.LimitReader(f,1024*1024+1))
 if err!=nil || len(b)>1024*1024{return nil,errors.New("invalid CA file size")}
 p:=x509.NewCertPool()
 if !p.AppendCertsFromPEM(b){return nil,errors.New("CA file contains no valid certificates")}
 return p,nil
}

