package main
import (
  "bufio"
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "flag"
  "fmt"
  "log"
  "os"
  "strconv"
  "strings"
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

func checkErr(err error) {
  if err != nil {
    log.Fatalf("%s", err)
    os.Exit(1)
  }
}

func main() {
  keyFilePtr := flag.String("keyFile", "key.pem", "path for private key output")
  jsonFilePtr := flag.String("jsonFile", "level.json", "path for level json output")
  flag.Parse()
  
  level := &Level{}
  
  reader := bufio.NewReader(os.Stdin)
  
  fmt.Print("Please enter the level name: ")
  levelName, err := reader.ReadString('\n')
  checkErr(err)
  level.Name = strings.TrimSpace(levelName)
  
  fmt.Print("Please enter the level description: ")
  levelDescription, err := reader.ReadString('\n')
  checkErr(err)
  level.Description = strings.TrimSpace(levelDescription)
  
  fmt.Print("Please enter the level maintainer(s): ")
  levelMaintainer, err := reader.ReadString('\n')
  checkErr(err)
  level.Maintainer = strings.TrimSpace(levelMaintainer)
  
  fmt.Print("Please enter the level points as an integer: ")
  levelPoints, err := reader.ReadString('\n')
  checkErr(err)
  level.Points, err = strconv.Atoi(strings.TrimSpace(levelPoints))
  checkErr(err)
  
  fmt.Print("Please enter the level entry points as comma separated public key fingerprints: ")
  levelEntryPoints, err := reader.ReadString('\n')
  checkErr(err)
  level.LevelEntryPoints = strings.Split(strings.TrimSpace(levelEntryPoints), ",")
  
  fmt.Println("----")
  fmt.Printf("Exporting private key (for secret box) to %s...", *keyFilePtr)
  
  privKey, err := rsa.GenerateKey(rand.Reader, 2048)
  checkErr(err)
  
  keyOut, err := os.OpenFile(*keyFilePtr, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
  checkErr(err)
  
  pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
  
  keyOut.Close()

  fmt.Println("done")
  
  pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
  checkErr(err)

  pubKeyBytes := pem.EncodeToMemory(&pem.Block{
      Type:  "RSA PUBLIC KEY",
      Bytes: pubASN1,
  })
  
  level.PublicKey = string(pubKeyBytes)
  
  level.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(pubASN1))
  fmt.Printf("Level fingerprint is: %s\n", level.Fingerprint)
  
  levelString, err := json.Marshal(level)
  checkErr(err)
  
  hash := sha256.New()
  hash.Write(levelString)
  digest := hash.Sum(nil)
  
  signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest)
  checkErr(err)
  
  level.Signature = base64.StdEncoding.EncodeToString(signature)
  
  levelString, err = json.Marshal(level)
  checkErr(err)
  
  jsonOut, err := os.OpenFile(*jsonFilePtr, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
  checkErr(err)
  
  jsonOut.Write(levelString)
  jsonOut.Close()
  
  fmt.Printf("Wrote level JSON to %s\n", *jsonFilePtr)
}