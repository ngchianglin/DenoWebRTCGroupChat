/*

Simple deno app to add a user into a password file for groupchat application.  
The password file is located at pass/passwd
The directory pass must be present. Create it if necessary. 
The app uses a 14 digit random salt plus sha256 hashing from deno standard library.
This is for simplicity. For stronger security, bcrypt or scrypt or some other 
modern password derivation algorithm should be used instead. 

deno run --allow-write=./ --allow-read=./ pass-util.ts [username]

Note that dupliate userid will not be checked. 

Ng Chiang Lin
Sep 2020

*/

import { readLines } from "https://deno.land/std@0.71.0/io/mod.ts";
import { createHash } from "https://deno.land/std@0.71.0/hash/mod.ts";


let passdir = 'pass';
let password_file_tmp = passdir + "/passwd.tmp";
let password_file = passdir + "/passwd";
let random_char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ()&[]abcdefghijklmnopqrstuvwxyz0123456789-!@#$%^";
let random_length = 14;
let password_min_length = 16; 

let args = Deno.args;

if (args.length != 1)
{
    console.log("Adds a user to the groupchat password file"); 
    console.log("Usage: deno --allow-write=./ pass-util.ts [username]");
    Deno.exit(1);
}

let username = args[0]; 

if(username.length < 3 || username.includes(":"))
{
    console.log("username must be minimum 3 characters and cannot contain \":\"");
    Deno.exit(1);
}

const encoder = new TextEncoder();

let done = false;
let pass = '';

while (!done)
{
    Deno.stdout.write(encoder.encode("Enter password: "));
    pass = '';
  
    for await (pass of readLines(Deno.stdin)) 
    {
       break;
    }

    if(pass.length < password_min_length)
    {
        console.log("Password must be at least ", password_min_length);
    }
    else
    {
        done = true; 
    }
    
}


let i:number;
let random_string = "";
for (i = 0 ; i < random_length; i++)
{
    let len = random_char_set.length;
    let ran = Math.floor((Math.random() * len) + 1);

    random_string = random_char_set.charAt(ran) + random_string;

}


pass = pass + random_string; 

const hash = createHash("sha256");
hash.update(pass);
const hexstring = hash.toString();

let line = username + ":" + random_string + ":" + hexstring + "\n";

try
{
    Deno.openSync(password_file,{read:true});
}
catch(err)
{
    /* passwd file not found */
    await Deno.writeTextFile(password_file, line, {append: true});
    Deno.exit(0);
}



Deno.copyFile(password_file, password_file_tmp).then
(
    () => {
        Deno.writeTextFile(password_file_tmp, line, {append: true});
    }
)
.then
(
   () => {
    Deno.rename(password_file_tmp, password_file);
   }

)
.catch(

  (err) => {
    console.log("An error occurred " + err);
    Deno.exit(1);
  }

);

