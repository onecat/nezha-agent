//go:build linux

package monitor

import (
 "os"
 "math"
 "path/filepath"
 "strconv"
 "strings"
)

// Linux DRM sysfs exposes gpu_busy_percent on some AMD and Intel devices.
// No external commands, vendor APIs or network calls are required.
// Missing or inaccessible telemetry remains unsupported (zero).
func gpuCards(root string) []string {
 paths,err:=filepath.Glob(filepath.Join(root,"card[0-9]*","device","gpu_busy_percent"))
 if err!=nil{return nil}
 return paths
}
func gpuReading(path string)(float64,bool){
 b,err:=os.ReadFile(path)
 if err!=nil||len(b)>32{return 0,false}
 v,err:=strconv.ParseFloat(strings.TrimSpace(string(b)),64)
 if err!=nil||math.IsNaN(v)||math.IsInf(v,0)||v<0||v>100{return 0,false}
 return v,true
}
func gpuUsageAt(root string) float64 {
 paths:=gpuCards(root)
 var total float64
 var count int
 for _,path:=range paths{
  if value,ok:=gpuReading(path);ok{total+=value;count++}
 }
 if count==0{return 0}
 return total/float64(count)
}
func gpuNamesAt(root string) []string{
 paths:=gpuCards(root)
 names:=make([]string,0,len(paths))
 for _,path:=range paths{
  if _,ok:=gpuReading(path);!ok{continue}
  card:=filepath.Base(filepath.Dir(filepath.Dir(path)))
  vendor,err:=os.ReadFile(filepath.Join(filepath.Dir(path),"vendor"))
  if err!=nil||len(vendor)>32{names=append(names,card);continue}
  id:=strings.TrimSpace(string(vendor))
  switch id {
  case "0x1002":names=append(names,card+" (AMD)")
  case "0x8086":names=append(names,card+" (Intel)")
  default:names=append(names,card)
  }
 }
 return names
}
func gpuUsage()float64{return gpuUsageAt("/sys/class/drm")}
func gpuNames()[]string{return gpuNamesAt("/sys/class/drm")}
