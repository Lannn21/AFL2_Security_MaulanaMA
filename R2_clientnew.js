const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");   

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
const users = new Map();

// membuat key pair 
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

socket.on("connect", () => {
  console.log("Connected to the server");

  socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key)); 
    console.log(`There are currently ${users.size} users in the chat`);

    rl.question("Enter your username: ", (input) => {
      username = input;
      registeredUsername = input;
      console.log(`Welcome, ${username} to the chat`);

      socket.emit("registerPublicKey", { // username dan public key diregister
        username,
        publicKey: publicKey.export({ type: "pkcs1", format: "pem" }),
      });
      rl.prompt();

      // input pesan 
      rl.on("line", (message) => {
        if (message.trim()) {
          if ((match = message.match(/^!impersonate (\w+)$/))) {
            username = match[1];
            console.log(`Now impersonating as ${username}`);
          } else if (message.match(/^!exit$/)) {
            username = registeredUsername;
            console.log(`Now you are ${username}`);
          } else {

            const sign = crypto.createSign("sha256");  // membuat signature dengan sha 256
            sign.update(message); 
            sign.end();
            const signature = sign.sign(privateKey, "hex"); 

            socket.emit("message", { // mengirimkan pesan,username,signature ke server
              username,
              message,
              signature, 
            });
          }
        }
        rl.prompt();
      });
    });
  });
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
    const { username: senderUsername, message: senderMessage, signature } = data;
  
    // cek identitas pengirim
    if (senderUsername !== username) {
      const senderPublicKey = users.get(senderUsername);
  
      if (senderPublicKey && signature) {
        const verify = crypto.createVerify("sha256"); // verifikasi key
        verify.update(senderMessage);
        verify.end();

        const isVerified = verify.verify(senderPublicKey, signature, "hex");
  
        if (isVerified) {
          console.log(`${senderUsername}: ${senderMessage}`); // pesan terkirim
        } else {
          console.log(`${senderUsername}: ${senderMessage}`); // pesan terkirim, impersonate
          console.log(`Warning: This user is fake`);
        }
      } else if (!signature) {
        // cek signature
        console.log(`Warning: ${senderUsername} sent a message without a signature`);
      } else {
        // cek public key
        console.log(`Warning: No public key found for ${senderUsername}`);
      }
    }
  
    rl.prompt();
  });
  
socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});