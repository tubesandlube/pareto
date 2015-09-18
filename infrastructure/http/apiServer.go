//TODO
// break out into packages
// create level
// start level
// finish level
// boltdb
// leaderboards
// score level package based on consensus e.g. uploaded level requires some people to complete it before scores are counted

package main
import (
  "crypto"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "log"
  "net/http"

  "github.com/gorilla/mux"
)
 
 type Level struct {
     Name   string
     Description string
     Points int
     Maintainer string
     LevelEntryPoints []string
     Fingerprint string
     PublicKey string
     Signature string
 }

func CreateLevel(resp http.ResponseWriter, req *http.Request) {
  decoder := json.NewDecoder(req.Body)
  var level Level   
  err := decoder.Decode(&level)
  if err != nil {
    log.Printf("%s\n", err)
  }
  signature, err := base64.StdEncoding.DecodeString(level.Signature)
  level.Signature = ""
  log.Printf("%s\n", signature)
  
  block,_ := pem.Decode([]byte(level.PublicKey))
  if block == nil {
    log.Printf("error loading pub key")
  }
  
  pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil {
    log.Printf("%s\n", err)
  }
  
  levelString, err := json.Marshal(level)
  if err != nil {
    log.Printf("%s\n", err)
  }
  
  hash := sha256.New()
  hash.Write(levelString)
  digest := hash.Sum(nil)
  
  err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, digest, signature)
  if err != nil {
    fmt.Printf("rsa.VerifyPKCS1v15 error: %V\n", err)
  }
  
  log.Printf("Signature is ok!\n")
  
  resp.Write([]byte(fmt.Sprintf("Hello!")))
}

func main() {
  
  mx := mux.NewRouter()

  mx.HandleFunc("/levels", CreateLevel).Methods("POST")

  http.ListenAndServe(":8080", mx)
}