# ECDH architecture
Lora protocol encrypts the messages between the sensor and the gateway but the symmetric secret being used in the process is accesible to anyone who has access to the gateway. Riddle and Code solves this problem by adding another layer of encryption above the payload. To accomplish this we planned a secure architecture which consists of initial key calculation & storage on SECURE - ELEMENT on Raspberry pi . And encryption with the calculated secret later on the LoRa sensor. 
## Initial Key Provisioning
Secure Element is an independent entity that stores a secp256r1 keypair in  it's locked identity slot. Secret part of the keypair can not be extracted from the device, it can be used to do ECDSA and create digital signatures. Digital signature then can be used to prove ownership of any data. 

During the provisioning phase Secure Element will be moved from the LoRa sensor to raspberry-pi since it has a TCP-IP stack at ready for communications with the END-POINT.

Raspberry Pi and the Server must know each other before starting the communication. This can be accomplished if both of them has the secp256r1 public key of the other party. 

-  A static keypair must be generated on the END-POINT, and the public key part must be shared with the raspberry.
-   Static public key of the Raspberry must be shared with the END-POINT. (keypair in the locked slot. )
* Along with the static keypairs ; we need a ephemeral key pair on both sides to calculate a shared secret.
* Static key pairs will be used to authenticate, the devices againist each other. Temporal key pairs will be used to calculate the Diffie-Hellman shared secret.


***

## Diffie - Hellman Key Exchange

The process starts with asymettric keypairs and utilizes it to find one symmetric secret.It can be summarized roughly as follows :

* Both parties create a secret using secure random methods, this secret  will act as the private key of the ephemeral keypair. From that private key , corresponding public key will be calculated doing scalar multiplication.
* Ephemeral public key Raspberry will be forwarded to the END-POINT, Ephemeral Public key of END-POINT will be forwared to Raspberry. 
* To prove that this ephemeral public key really comes from the auhorized devices the sender has to sign the public key with the static private key (device identity).
* When the receiver collects the ephemeral public key of the other party, it has to run ECDSA function with the already provisioned  static public key of the other device .
* If the outcome of the verify function is true, then the device will proceed to derive the shared secret through EC multiplication. ( Raspberry ephemeral private key *  END-POINT Ephemeral  public key = END-POINT ephemeral private key  * Raspberry ephemeral public key = Shared Secret )
* After the succesful calculation the secret will be written to the Secure- Element. Secure element will then be removed from the raspberry pi and plugged back into the LoRa sensor to act as a secure storage and crypto accelerator for standart operations.
* The END-POINT can associate the static public key of the Secure Element with the shared secret, and can create a list of dictionaries such as :   { public_key1 : shared_secretx  ,public_key2 : shared_secrety , ...}
* This process called **provisioning**  must be followed for each Lora device with a secure element. 
***
## Encryption Using the Shared Secret

Supported encryption methods for the LoRa sensor are as follows : 

* AES-CBC 128 with CMAC between LoRa sensor and the gateway. (This step is handled automatically by Lora stack) .
* AES-CTR 128 between LoRa sensor and the endpoint.

Basically we will be encrypting the payload twice in two layers , outer layer will be stripped after the payload has been processed inside the gateway, and will be forwarded to the END-POINT in an encrypted custom CAYENNE format.

***

An example END-POINT implemented in rust can be found [here .](https://github.com/RiddleAndCode/rust-ecdh-backend-example) 