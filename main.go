package main

import (
	"corvaglia/galaxy/concorde"
	"log"
)

func main() {
	//Generated alice and bob's keys
	alice := concorde.New()
	bob := concorde.New()
	//alice := concorde.NewFromFile(filename)
	//Get Bob's public key or encapsulation key
	bob_public_key := bob.GetEncapsulationKey()
	//Had alice generate the shared secret and encrypt it with bob's key
	cipher := alice.GenerateCipheredSecret(bob_public_key)
	//Have bob recieve it and decrypt it then store the secret
	bob.AcceptCipheredSecret(cipher)
	//alice.ExportDecapsulationKeyToFile(filename)
	//alice.ExportEncapsulationKeyToFile(filename)
	//Have alice encrypt a message
	message := alice.AES256Encrypt([]byte("Hello World!"))
	//Have bob decypt it using the shared secret
	log.Println(string(bob.AES256Decrypt(message)))
	//Prints Hello World! which means everything worked correctly
	//There was a quantum safe key exchange using LM-KEM-1024 and then
	//and then AES-256 was used for the message based on the exchanged key.
}