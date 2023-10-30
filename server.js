const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');

let sql; 
const sqlite3 = require('sqlite3').verbose(); 

//create database. 
let db = new sqlite3.Database("./Project1/js/totally_not_my_privateKeys.db");



//create a tbl on start
sql = `CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`; 
db.run(sql); 

//delete table
//db.run(`DELETE FROM keys`)

//db.run("DROP TABLE keys"); 



//query 
/*sql = `SELECT * FROM keys`;
db.all(sql, [], (err, rows)=>{
  if(err) return console.error(err.message); 
  rows.forEach((row)=>{
    console.log(row); 
  }); 
  console.log("end test"); 
})
*/


const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
//async generate the key pairs using jose. 
  async function generateKeyPairs() {
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    //console.log("keyPair: ", keyPair.toPEM(true)); 
    //console.log("expired: ", expiredKeyPair.toPEM(true)); 
  }

  //query 
/*sql = `SELECT * FROM keys`; 
db.all(sql, [], (err, rows)=>{
  if(err) return console.error(err.message); 
  rows.forEach((row)=>{
    console.log(row); 
  }); 
})
*/

//generate non-expired tokens from the information in the database. 
function generateToken() {
    //select non-expired keys, kids, and expiration dates. 
  sql = `SELECT * FROM keys WHERE exp > ?`;
  db.all(sql, [Math.floor(Date.now() / 1000)], (err, rows) => {
    if (err) {
      return console.error(err.message);
    }
      //grab the first result. 
      const returnedKey = rows[0];
     // console.log("row0:", returnedKey); 
     // console.log(returnedKey); 
      const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      const options = {
        algorithm: 'RS256',
        header: {
          typ: 'JWT',
          alg: 'RS256',
          kid: returnedKey.kid//use the kid that was grabbed from the database. 
        }
      }
      //sign the token using the key from the database, payload, and options. 
      token = jwt.sign(payload, returnedKey.key, options);  

  });
}

function generateExpiredJWT() {
  //sql command
    //get keys, kids where they are expired. 
  sql =  `SELECT * FROM keys WHERE exp > ?`; 
  db.all(sql, [Math.floor(Date.now() / 1000) - 30000], (err,rows)=>
  {
    if (err) {
      return console.error(err.message);
    }
//grab the first row 
    const returnedExpiredKey = rows[0]; 
  //console.log(rows[0]); 
    const payload = {
      user: 'sampleUser',
      iat: Math.floor(Date.now() / 1000) - 30000,
      exp: Math.floor(Date.now() / 1000) - 3600
    };
    const options = {
      algorithm: 'RS256',
      header: {
        typ: 'JWT',
        alg: 'RS256',
        kid: returnedExpiredKey.kid//use the kid from the database. 
      }
    };
  //sign the expired token with the key returned from the database, options, and payloads. 
    expiredToken = jwt.sign(payload, returnedExpiredKey.key, options);
  }); 
  
}

//refuse unacceptable requests. 
app.all('/auth', (req, res, next) => {
  //reads priv key from db. 

  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

//only get requests 
app.all('/.well-known/jwks.json', (req, res, next) => {  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

//gets the jwt. checking against the public key. Gets public key
app.get('/.well-known/jwks.json', (req, res) => {
  //reads all valid priv keys from the db. 
  sql = `SELECT * FROM keys WHERE exp > ?`; 
  validKeys = db.all(sql, [Math.floor(Date.now() / 1000)], (err, rows)=>
  {
    rows.forEach((row)=>{
    if([row].filter(key => !key.expired))
      return [keyPair].filter(key => !key.expired);
    }); 
    
  }); 
  

  //creates a JWKS response based on those keys. 
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', (req, res) => {//returns an unexpired signed jwt on post. private key. 

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
  
});

//promise. so it should do the gen key pairs first. 
generateKeyPairs().then(() => {
  //insert key into tbl 
  sql = `INSERT INTO keys(key, exp) VALUES (?,?)`; 
   db.run(sql, [keyPair.toPEM(true), Math.floor(Date. now() / 1000) + 3600], (err)=>{
    if(err) return console.error(err.message); 
  }); 
  //insert expired key into tbl 
  sql = `INSERT INTO keys(key, exp) VALUES (?,?)`; 
   db.run(sql, [expiredKeyPair.toPEM(true), Math.floor(Date. now() / 1000) - 3600], (err)=>{
    if(err) return console.error(err.message); 
  }); 
  //insertkey into 
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
