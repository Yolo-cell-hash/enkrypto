const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const { name } = require('ejs');
const affine = require("@haydenhigg/affine");
const { encryptString, decryptString } = require("@gykh/caesar-cipher");
const { decoder, encoder } = require('@karlbateman/nero');
const C = require('js-ktc');
const aes256 = require('aes256');
const CryptoJS = require("crypto-js");
const SHA256 = require("crypto-js/sha256");
var md5 = require('md5');



const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));

/* VARIABLES */
var alphabets=["a","b",'c','d','e','f','g','h','i','j',
'k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'];

var userInput='';
var userInput_first_word_lc='';
var idex_of_userIp_lc=''
var Ckey=Number("");
var key="";
var Dkey='';
var encrypted_word = "";
var userInput_array=[];
var userInput_first_word="";
var encrypted_word_first_word="";
var encrypted_word_array=[];
var decrypted_word_array=[];
var encrypted_word_first_word='';
var decrypted_word_first_word='';
var decrypted_word="";

var vignere_key="";

/* HOMEPAGE GET */
app.get("/", function(req,res){
    res.render("home");
  });

  /*CEASER CIPHER POST */
  app.post('/ceaser-cipher',function(req,res){

    var userInput = req.body.user_word;
    userInput_array= userInput.split("");
    userInput_first_word= userInput_array[0];
    Ckey = Number(req.body.encryption_key);
 
  encrypted_word = encryptString(userInput,Ckey);
  encrypted_word_array= encrypted_word.split("");
  encrypted_word_first_word= encrypted_word_array[0];
  res.redirect('/ceaser-cipher')
  })

/* CEASER DECIPHER POST */
  app.post('/ceaser-decipher',function(req,res){

    var DuserInput = req.body.user_word;
    userInput_array= DuserInput.split("");
    userInput_first_word= userInput_array[0];
    Dkey = req.body.encryption_key;
    
    const caesarDecoded = (s, n) => {
      let alphabet = 'abcdefghijklmnopqrstuvwxyz'
      let lc = alphabet.replace(/\s/g, '').toLowerCase().split('')
      let uc = alphabet.replace(/\s/g, '').toUpperCase().split('')
    
      return Array.from(s)
        .map((v) => {
          if (lc.indexOf(v.toLowerCase()) === -1 || uc.indexOf(v.toUpperCase()) === -1) {
            return v
          }
    
          let lcEncryptIndex = (lc.indexOf(v.toLowerCase()) - n) % alphabet.length
          lcEncryptIndex = lcEncryptIndex < 0 ? lcEncryptIndex + alphabet.length : lcEncryptIndex
          const lcEncryptedChar = lc[lcEncryptIndex]
    
          let ucEncryptIndex = (uc.indexOf(v.toUpperCase()) - n) % alphabet.length
          ucEncryptIndex = ucEncryptIndex < 0 ? ucEncryptIndex + alphabet.length : ucEncryptIndex
          const ucEncryptedChar = uc[ucEncryptIndex]
    
          return lc.indexOf(v) !== -1 ? lcEncryptedChar : ucEncryptedChar
        })
        .join('')
    }

  
  decrypted_word=caesarDecoded(s=DuserInput,n=Dkey)

  decrypted_word_array= decrypted_word.split("");
  decrypted_word_first_word= decrypted_word_array[0];
  res.redirect('/ceaser-decipher')

})

/*CEASER CIPHER GET */
  app.get('/ceaser-cipher', function(req,res){
    var data={
      key:Ckey,
      code_word:encrypted_word,
      first_word:userInput_first_word,
      efirst_word:encrypted_word_first_word
  }
  res.render("ceaser_cipher",{data:data});
  encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
  Ckey="";
  decrypted_word_array.length=0;
  userInput_array.length=0;
  userInput_first_word="";
  encrypted_word_first_word='';  

})

/*CEASER DECIPHER GET */
app.get('/ceaser-decipher', function(req,res){
  var data={
    key:Dkey,
    code_word:decrypted_word,
    first1_word:userInput_first_word,
    efirst_word:decrypted_word_first_word
}
res.render("decrypt_ceaser-cipher",{data:data});
decrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
Dkey="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
decrypted_word_first_word='';  

})

/*VIGNERE CIPHER POST */
  app.post('/vignere-cipher',function(req,res){

    userInput = req.body.user_word;
    userInput_array= userInput.split("");
    userInput_first_word= userInput_array[0];
    key = req.body.encryption_key;
 

    function generateKey(str,key)
    {
         
         key=key.split("");
        if(str.length == key.length)
            return key.join("");
        else
        {
            let temp=key.length;   
            for (let i = 0;i<(str.length-temp) ; i++)
            {
                 
                key.push(key[i % ((key).length)])
            }
        }
        return key.join("");
    }
     
    // This function returns the encrypted text
    // generated with the help of the key
    function cipherText(str,key)
    {
        let cipher_text="";
      
        for (let i = 0; i < str.length; i++)
        {
            // converting in range 0-25
            let x = (str[i].charCodeAt(0) + key[i].charCodeAt(0)) %26;
      
            // convert into alphabets(ASCII)
            x += 'A'.charCodeAt(0);
      
            cipher_text+=String.fromCharCode(x);
        }
        return cipher_text;
    }


  vignere_key = generateKey(str=userInput,key=key);
  encrypted_word = cipherText(userInput,vignere_key)
  encrypted_word_array= encrypted_word.split("");
  encrypted_word_first_word= encrypted_word_array[0];
  res.redirect('/vignere-cipher')
  })

/*VIGNERE CIPHER GET */
app.get('/vignere-cipher', function(req,res){
  var data={
    key:key,
    v_key:vignere_key,
    code_word:encrypted_word,
    userWord:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("vignere_cipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
vignere_key="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word=''; 
userInput=''; 

})

/*VIGNERE DECIPHER POST */
app.post('/vignere-decipher',function(req,res){

  userInput = req.body.user_word;
  userInput_array= userInput.split("");
  userInput_first_word= userInput_array[0];
  key = req.body.encryption_key;


  function generateKey(str,key)
  {
       
       key=key.split("");
      if(str.length == key.length)
          return key.join("");
      else
      {
          let temp=key.length;   
          for (let i = 0;i<(str.length-temp) ; i++)
          {
               
              key.push(key[i % ((key).length)])
          }
      }
      return key.join("");
  }
   
  // This function returns the encrypted text
  // generated with the help of the key
  function originalText(cipher_text,key)
  {
      let orig_text="";
    
      for (let i = 0 ; i < cipher_text.length ; i++)
      {
          // converting in range 0-25
          let x = (cipher_text[i].charCodeAt(0) -
                      key[i].charCodeAt(0) + 26) %26;
    
          // convert into alphabets(ASCII)
          x += 'A'.charCodeAt(0);
          orig_text+=String.fromCharCode(x);
      }
      return orig_text;
  }
   


vignere_key = generateKey(str=userInput,key=key);
encrypted_word = originalText(userInput,vignere_key)
encrypted_word_array= encrypted_word.split("");
encrypted_word_first_word= encrypted_word_array[0];
res.redirect('/vignere-decipher')
})

/*VIGNERE DECIPHER GET */
app.get('/vignere-decipher', function(req,res){
  var data={
    key:key,
    v_key:vignere_key,
    code_word:encrypted_word,
    userWord:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("vignere_decipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
vignere_key="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word=''; 
userInput=''; 

})

/*AFFINE CIPHER POST */
  app.post('/affine-cipher',function(req,res){

    var userInput = req.body.user_word;
    userInput_array= userInput.split("");
    userInput_first_word= userInput_array[0];
    key = req.body.encryption_key_a;
    Dkey = req.body.encryption_key_b;
 
  encrypted_word = affine.encrypt(key,Dkey,userInput);
  encrypted_word_array= encrypted_word.split("");
  encrypted_word_first_word= encrypted_word_array[0];
  res.redirect('/affine-cipher')
  })

/*AFFINE CIPHER GET */
app.get('/affine-cipher', function(req,res){
  var data={
    key_1:key,
    key_2:Dkey,
    code_word:encrypted_word,
    userWord:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("affine-cipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
Dkey="";
vignere_key="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word=''; 
userInput=''; 

})
   
/*AFFINE DECIPHER GET */
app.get('/affine-decipher', function(req,res){
  var data={
    key_1:key,
    key_2:Dkey,
    code_word:encrypted_word,
    userWord:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("affine-decipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
Dkey="";
vignere_key="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word=''; 
userInput=''; 
})

/*AFFINE DECIPHER POST */
app.post('/affine-decipher',function(req,res){

  var userInput = req.body.user_word;
  userInput_array= userInput.split("");
  userInput_first_word= userInput_array[0];
  key = req.body.encryption_key_a;
  Dkey = req.body.encryption_key_b;

encrypted_word = affine.decrypt(key,Dkey,userInput);
encrypted_word_array= encrypted_word.split("");
encrypted_word_first_word= encrypted_word_array[0];
res.redirect('/affine-decipher')
})


/*SUBSTITUTION CIPHER POST */
app.post('/substitution-cipher',function(req,res){

  userInput = req.body.user_word;
  userInput_array= userInput.split("");
  userInput_first_word= userInput_array[0];

  var userInput_LowerCase=userInput.toLowerCase();
  var userInput_LCarray= userInput_LowerCase.split("");
  userInput_first_word_lc= userInput_LCarray[0];

encrypted_word = encoder(userInput);
idex_of_userIp_lc=alphabets.indexOf(userInput_first_word_lc)+1;
encrypted_word_array= encrypted_word.split("");
encrypted_word_first_word= encrypted_word_array[0];
res.redirect('/substitution-cipher')
})

/*SUBSTITUTION CIPHER GET */
app.get('/substitution-cipher', function(req,res){
  var data={
    userIp:userInput,
    code_word:encrypted_word,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word,
    index_of_lc_word:idex_of_userIp_lc,
}
res.render("substitution-cipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
decrypted_word_array.length=0;
userInput='';
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word='';
idex_of_userIp_lc='';  
})

/*SUBSTITUTION DECIPHER POST */
app.post('/substitution-decipher',function(req,res){

  userInput = req.body.user_word;
  userInput_array= userInput.split("");
  userInput_first_word= userInput_array[0];

encrypted_word = decoder(userInput);
encrypted_word_array= encrypted_word.split("");
encrypted_word_first_word= encrypted_word_array[0];
res.redirect('/substitution-decipher')
})

/*SUBSTITUTION DECIPHER GET */
app.get('/substitution-decipher', function(req,res){
  var data={
    userIp : userInput,
    code_word:encrypted_word,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("substitution-decipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
decrypted_word_array.length=0;
userInput='';
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word='';  

})

/*KEYWORD CIPHER POST */
  app.post('/keyword-cipher',function(req,res){

    var userInput = req.body.user_word;
    userInput_array= userInput.split("");
    userInput_first_word= userInput_array[0];
    key = (req.body.encryption_key);

    let ktc = new C(key) 
   encrypted_word = ktc.encrypt(userInput,Ckey);
   encrypted_word_array= encrypted_word.split("");
   encrypted_word_first_word= encrypted_word_array[0];
   res.redirect('/keyword-cipher')
  })

/*KEYWORD CIPHER GET */
app.get('/keyword-cipher', function(req,res){
  var data={
    key:key,
    code_word:encrypted_word,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("keyword-cipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word='';  
})

/*KEYWORD DECIPHER POST */
app.post('/keyword-decipher',function(req,res){

  var userInput = req.body.user_word;
  userInput_array= userInput.split("");
  userInput_first_word= userInput_array[0];
  key = (req.body.encryption_key);

  let ktc = new C(key) 
 encrypted_word = ktc.decrypt(userInput,Ckey);
 encrypted_word_array= encrypted_word.split("");
 encrypted_word_first_word= encrypted_word_array[0];
 res.redirect('/keyword-decipher')
})

/*KEYWORD DECIPHER GET */
app.get('/keyword-decipher', function(req,res){
  var data={
    key:key,
    code_word:encrypted_word,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("keyword-decipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
decrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word='';  
})

/*AES-ECB 256 CIPHER POST */
app.post('/aes256-cipher',function(req,res){

  userInput = req.body.user_word;
  key = req.body.encryption_key;

  var buffer = Buffer.from(userInput);
  encrypted_word = aes256.encrypt(key, userInput);
/*   encrypted_word = aes256.encrypt(key, buffer);*/
encrypted_word_array= encrypted_word.split("");
encrypted_word_first_word= encrypted_word_array[0];
userInput_array= userInput.split('');
userInput_first_word=userInput_array[0];

res.redirect('/aes256-cipher')
})

/*AES-ECB 256 CIPHER GET */
app.get('/aes256-cipher', function(req,res){
  var data={
    key:key,
    code_word:encrypted_word,
    userWord:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("aes256-cipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
encrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word=''; 
userInput=''; 
})

/*AES-ECB 256 DECIPHER POST */
app.post('/aes256-decipher',function(req,res){

  userInput = req.body.user_word;
  key = req.body.encryption_key;

  encrypted_word = aes256.decrypt(key, userInput);
/*   encrypted_word = aes256.encrypt(key, buffer);*/
encrypted_word_array= encrypted_word.split("");
encrypted_word_first_word= encrypted_word_array[0];
userInput_array= userInput.split('');
userInput_first_word=userInput_array[0];

res.redirect('/aes256-decipher')
})

/*AES-ECB 256 DECIPHER GET */
app.get('/aes256-decipher', function(req,res){
  var data={
    key:key,
    code_word:encrypted_word,
    userWord:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("aes256-decipher",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
key="";
encrypted_word_array.length=0;
userInput_array.length=0;
userInput_first_word="";
encrypted_word_first_word=''; 
userInput=''; 
})


/*SHA-256 POST */
app.post('/sha-256',function(req,res){

userInput = req.body.user_word;
encrypted_word = SHA256(userInput);
res.redirect('/sha-256')
})

/*SHA-256 GET */
app.get('/sha-256', function(req,res){
  var data={
    code_word:encrypted_word,
    u_word:userInput,
    first_word:userInput_first_word,
    efirst_word:encrypted_word_first_word
}
res.render("sha-256",{data:data});
encrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
userInput='';
})


/* HMAC-SHA1 POST */
app.post('/hmac-sha1',function(req,res){

  userInput = req.body.user_word;
  Dkey = req.body.encryption_key;

decrypted_word=CryptoJS.HmacSHA1(userInput,Dkey);
res.redirect('/hmac-sha1')
})


/*HMAC-SHA1 GET */
app.get('/hmac-sha1', function(req,res){
  var data={
    key:Dkey,
    code_word:decrypted_word,
    d_ip:userInput,
}
res.render("hmac-sha1",{data:data});
decrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
Dkey="";
userInput=""
})

/* MD5 POST */
app.post('/md5',function(req,res){

  userInput = req.body.user_word;

decrypted_word=md5(userInput);
res.redirect('/md5')
})

/*MD5 GET */
app.get('/md5', function(req,res){
  var data={
    code_word:decrypted_word,
    d_ip:userInput,
}
res.render("md5",{data:data});
decrypted_word="";  //RESETS the variable so that value gets removed after page refreshes
Dkey="";
userInput=""
})



/* SERVER ACTIVATION */

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function(){
  console.log("Server ativated at port successfully");
});










