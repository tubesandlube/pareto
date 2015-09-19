package main

import (
  "bufio"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
  "encoding/pem"
  "flag"
  "fmt"
  "os"
  "strings"
  
  "golang.org/x/crypto/pbkdf2"
)

func checkErr (err error) {
  if err != nil {
    panic(err)
  }
}

func main() {
  keyFilePtr := flag.String("keyFile", "", "path for private key to lock up")
  flag.Parse()
  
  if (*keyFilePtr == "") {
    fmt.Println("-keyFile is required")
    os.Exit(1)
  }
  
  reader := bufio.NewReader(os.Stdin)
  
  fmt.Print("Please enter the first half of the input (usually a md5 of a file): ")
  firstHalf, err := reader.ReadString('\n')
  checkErr(err)
  firstHalf = strings.TrimSpace(firstHalf)
  
  fmt.Print("Please enter the second half of the input (usually a result from a filesystem or log): ")
  secondHalf, err := reader.ReadString('\n')
  checkErr(err)
  secondHalf = strings.TrimSpace(secondHalf)
  
  combinedKey := firstHalf + secondHalf
  
  fmt.Println("-------\n")
  
  salt := make([]byte, 128)
  _, err = rand.Read(salt)
  checkErr(err)
  
  derivedKey := pbkdf2.Key([]byte(combinedKey), salt, 4096, 32, sha256.New)

  aesCipher, err := aes.NewCipher(derivedKey)
  checkErr(err)

  aesMode, err := cipher.NewGCM(aesCipher)
  checkErr(err)
  
  pemFile, err := os.Open(*keyFilePtr)
  checkErr(err)

  pemInfo, err := pemFile.Stat()
  checkErr(err)
  pemBytes := make([]byte, pemInfo.Size())
  buffer := bufio.NewReader(pemFile)
  _, err = buffer.Read(pemBytes)
  checkErr(err)
  
  privateKey, _ := pem.Decode([]byte(pemBytes))

  pemFile.Close()

  nonce := make([]byte, aesMode.NonceSize())
  _, err = rand.Read(nonce)
  checkErr(err)

  cipherText := aesMode.Seal(nil, nonce, privateKey.Bytes, derivedKey)
  
  combinedBytes := append(salt, nonce...)
  combinedBytes = append(combinedBytes, cipherText...)
  
  fmt.Printf("%s", pem.EncodeToMemory(&pem.Block{Type: "SECRET BOX", Bytes: combinedBytes}))
}
