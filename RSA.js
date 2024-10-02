const crypto = require("crypto");
const id = require("nanoid");
const messages = [];

class Person {
  constructor(name) {
    this.name = name;
    this.keys = this.generateKeys();
  }
  // Generates a public and a private key
  generateKeys() {
    const keyData = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

    return keyData;
  }
  //  Generates the encrypted message using the keys.
  message(messageTo, message) {
    const encryptedData = crypto.publicEncrypt(
      {
        key: messageTo.keys.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(message)
    );
    const messageObject = {
      from: this.name,
      to: messageTo.name,
      message: encryptedData,
      id: id.nanoid(),
    };
    messages.push(messageObject);
    return messageObject;
  }

  receiveMessage(id) {
    const message = messages.find((me) => me.id === id); // Small "db"
    if (!message) return console.log(`Message not found. ${id}`);
    const decryptedData = crypto.privateDecrypt(
      {
        key: this.keys.privateKey,
        // In order to decrypt the data, we need to specify the
        // same hashing function and padding scheme that we used to
        // encrypt the data in the previous step
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Encryption definitions and algorithms.
        oaepHash: "sha256",
      },
      message.message
    );
    return decryptedData;
  }
}

const James = new Person("James");
const Sophie = new Person("Sophie");
console.log(`
This is james!
James has a pretty hot goth gf called "Sophie", and he wants to send pictures to her.

But of course, James is a pretty intelligent man, and knows that the NSA and CIA is on him for
atleast 61 murder charges. So he encrypts his messages! Thanks god we live in Privacy Land!

So james picks up his phone and enters in [[insert privacy-wise messaging app that's not WhatsApp]]
and sends his pictures.
`);
const picture = James.message(Sophie, "picture.png");
console.log(picture);
console.log(`
Right now, hello.png is encrypted using the magic of RSA keys! When James was born
his mother was wise and created a **private** key and a **public key**.

So if anyone wants to send him a message they use his public key, and then reads his message with his private key.

Secure! Just like his picture!
`);
const pictureReceived = Sophie.receiveMessage(picture.id);
console.log(`New message: ${pictureReceived.toString()}`);
console.log(`
Well you look at that! Sophie just received the pictures!

When James sent his pictures, he used Sophie's public key, and sophie right now is unlocking the message
with her own private key.

Sophie decrypts the message and sees the images in her screen.
`);

console.log(`
Encryption, by Shiggy.

The end.`);
