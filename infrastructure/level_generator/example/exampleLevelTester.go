package main

import (
  "bufio"
  "bytes"
  "crypto"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/base64"
  "encoding/pem"
  "encoding/json"
  "fmt"
  "flag"
  "os"
  "time"
  "os/exec"
  "strings"
  
  "golang.org/x/crypto/pbkdf2"
)

var secretBox = `-----BEGIN SECRET BOX-----
JEjcq93+3iExQgTLawFi8X0wrYJw4nExARZDoFf02g9LtELpUub0q8fXipEP71VE
OI256n9GDbPiX0gJ/lR9XfqhD8OBm/u//wx4jPmOZr9xKS47eupphuoKIEfSdXEC
g333RM7dLZ9eyyVRsB3Hc/ZYArPrRDKKC02N0aIDwMVzo/g4QLqxXIbwH63OgWaH
ahDEv3v1IFyZrnKp8uEhhQCcsPv/mO/0IYetmEsr8kjCVoWIR6/HlKwgg6KXYsTB
yeemk9AH1gw45HxuuxdweU9Hxbw/3NrOi9mWHWFRpFINIFQmAJ2LS55TDv8FJ8D3
cDSstfZ659VJuWVfvYGvU7AU81ZhqT2aPVpZviDqL6j4KbxtbY3bV9sToax1oyqj
1YDi5nF+600YIEW8U9vLNmKd+sG4mZEfiXGOYa9ZgbUyj9x+vX3sPUzB67VVJjNY
X4JTUwiWZuVyrKxhXKZECvHhUmLJ8y6mxE+Z/hyT+KPfi8meIgnqT+pKnDQpFACC
Dpm/HIvH/oUxcVrKf/06SnSS2OKPrV3ZsSBY5C/dbd/OeEMsR3VBoHoYnhMMss4x
59ntERsZ08PBeXAYLS3eYf388Awb8XSI/O8mHJgVLDS9ZdwCGFsY8pAOmBWB8axB
xdPX2RA2pUlYwZJ5JlTIqiwPc0OgcLCeFNr2vNzvdbinO1RpogPYM/tcO432oZKP
SKoRVqou9mUMe8WOnnqgPtz61/QJnX/xzTc9Y51zqcRhHJW7idYN45oY72pE4/PR
MGCUTD1e5jfFdQuHB7eF6AnEermHq32k1QjZsng50qLrdVb3guiY66eL5LYNyUgv
vkulneP7aRIb0uAIz4s9uxrn2uR8dPShPK9v5LcKseg7TdEZRuc5ndPe0S/+Z3Rl
Hw+GsxwIq9Anj1VfTlscJfgjChxsyI9hxCkjOhoJRyBBmmoWsC+V6MGHuqSKDKUx
BCnaKohV0GIyblc+GIexGP4WB9x+yE/mynHhXGWSSoyM8w6tcfhrn4zAlFuPy0Xr
RCMUIblmf02rTabbjxEnXAYmmK4GCyLPVxrI/Oq9k3TS5fmWMeiVYkYm0UekWtjD
EHT7APhBySie6OfiqQEnFcCMqxSoU6wzED8tmjERyju9SuH2UVEubFlQBEGTxUGa
6vkvULvlH3YmQgjSayrk0I6Pkz4toZVTe/vKgSrVBc8NGGGjz0SXgVWr/zKVd4Rq
wzXO6tUf4zvf51m16gS9VzR6lW+uN1GccFa7N3WPr6ltE6Yaat1uegw552p5FoVC
ns2TFXVmirGwzQ2Hksf1rRH7zMcQe0ClVSZ8Fyh4VEV02a4dgzGDwkAMS3aCZXBM
et5+CWdwSKEoGGHL5zpmuGvmtQfUoX36NE6V2s6mVcmDmO5t3mQRZFDHJrRVM9Pz
6ApZLxVcRypaVraHcympJJI++lQxLERxznivKSX/NvmbqWdLRs1uETzC1l9EfH1+
C3KLg7oeKnQjg214fLk++IpEBbl2yb5qeoUNDg/agEbWYk6kymYSTv+NXyPytb+v
Zfu6C9oFsQCp7yFFV0jA5Qf9V3valCEYu1e+/TkmNrNoY23iME7WsNj1yRrKbX28
lQy+i12cpyKuSWrcv+GY7je5EJmVa+moKNvysPWoT8KqLNL6o+U66Wzy+N2ms3UK
JAnZVPLYvvklJNo8v8F5lRMhDLQsakSpwgcOuqgiDWaB6XsDrHK5DZa8A1M+NH4v
MsWCJ9NyA3wc/R7Q+IjJg5soXX86GEMWxpnqM5Hj7LKB8AJTb2vIU8DrKRA5BOku
2AV+Qg==
-----END SECRET BOX-----`

func getFirstHalf () []string {
  output, err := exec.Command("sh", "-c", "find / -type f | xargs md5sum | awk '{ print $1 }'").Output()
  checkErr(err)
  return strings.Split(string(output), "\n")
}

func getSecondHalf () []string {
  output, err := exec.Command("sh", "-c", "grep -o '[a-zA-Z][a-zA-Z]* [a-zA-Z][a-zA-Z]* [a-zA-Z][a-zA-Z]* [a-zA-Z][a-zA-Z]*' /var/log/messages").Output()
  checkErr(err)
  return strings.Split(string(output), "\n")
}

// DO NOT EDIT BELOW THIS LINE

type Status struct {
    Token          string
    CompletedAt    string
    Fingerprint    string
    Signature      string
}

func checkErr (err error) {
  if err != nil {
    panic(err)
  }
}

func main() {
  tokenPtr := flag.String("levelToken", os.Getenv("LEVEL_TOKEN"), "token from scoreboard API")
  flag.Parse()
  
  if (*tokenPtr == "") {
    fmt.Println("-levelToken is required")
    os.Exit(1)
  }
  
  secretBox, _ := pem.Decode([]byte(secretBox))
  buffer := bufio.NewReader(bytes.NewBuffer(secretBox.Bytes))
  
  saltBytes := make([]byte, 128)
  _, err := buffer.Read(saltBytes)
  checkErr(err)
  
  nonceBytes := make([]byte, 12)
  _, err = buffer.Read(nonceBytes)
  checkErr(err)
  
  cipherTextBytes := make([]byte, len(secretBox.Bytes) - 140)
  _, err = buffer.Read(cipherTextBytes)
  checkErr(err)
  
  privateKeyBytes := []byte{}
  
  firstHalves := getFirstHalf()
  secondHalves := getSecondHalf()
  
  for _, firstHalf := range firstHalves {
    for _, secondHalf := range secondHalves {
      combinedKey := firstHalf + secondHalf
      derivedKey := pbkdf2.Key([]byte(combinedKey), saltBytes, 4096, 32, sha256.New)
      aesCipher, err := aes.NewCipher(derivedKey)
      checkErr(err)

      aesMode, err := cipher.NewGCM(aesCipher)
      checkErr(err)
      
      privateKeyBytes, err = aesMode.Open(nil, nonceBytes, cipherTextBytes, derivedKey)
      
      if privateKeyBytes != nil {
        break
      }
    }
    
    if privateKeyBytes != nil {
      break
    }
  }
  
  if (privateKeyBytes == nil) {
    return
  }
  
  privKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
  privateKeyBytes = nil
  checkErr(err)
  
  pubASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
  checkErr(err)
  
  status := &Status{Token: *tokenPtr, CompletedAt: fmt.Sprintf("%s", time.Now()), Fingerprint: fmt.Sprintf("%x", sha256.Sum256(pubASN1))}
  
  statusString, err := json.Marshal(status)
  checkErr(err)
  
  hash := sha256.New()
  hash.Write(statusString)
  digest := hash.Sum(nil)
  
  signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest)
  privKey = nil
  checkErr(err)
  
  status.Signature = base64.StdEncoding.EncodeToString(signature)
  
  statusString, err = json.Marshal(status)
  checkErr(err)

  fmt.Printf("%s\n", statusString)
}