/* 
A simple deno websocket signaling server for a webrtc peer to peer groupchat
Ng Chiang Lin
Sep 2020
*/

import {serve} from "https://deno.land/std@0.71.0/http/server.ts";
import 
{
    acceptable,
    acceptWebSocket,
    isWebSocketCloseEvent,
    WebSocket
} from "https://deno.land/std@0.71.0/ws/mod.ts";
import { v4 } from 'https://deno.land/std@0.71.0/uuid/mod.ts';
import { readLines } from "https://deno.land/std@0.71.0/io/mod.ts";
import { createHash } from "https://deno.land/std@0.71.0/hash/mod.ts";
import * as log from "https://deno.land/std@0.71.0/log/mod.ts";


interface Command
{
    command:string,
    username?:string,
    password?:string
}

class ValidUser
{
    username: string;
    random: string;
    hash: string; 
    failed: number;
    locked: boolean;
   
    constructor(username:string, random:string, hash:string)
    {
        this.username = username;
        this.failed = 0;
        this.locked = false;
        this.random = random;
        this.hash = hash;
    }

}

class ChatUser 
{
    username : string;
    uuid: string; 
    sock: WebSocket;
    lastseen: number;

    constructor(username:string, sock:WebSocket)
    {
        this.username = username;
        this.sock = sock;
        this.uuid = v4.generate();
        this.lastseen = Date.now(); 
    }

}



let users = new Map<string, ChatUser>();
let passwd_users_list:Array<ValidUser> = [];
let socket_list:WebSocket[] = [];
let num_sockets = 0;
let server_start_time = 0;
let allow_relay = true; 

const PASSWD_FILE = "pass/passwd";
const MAX_FAILED_LOGIN = 5; 
const MAX_SOCKETS = 30;
const HOUSE_KEEP_INTERVAL = 15 * 60 * 1000; 
const KEEP_ALIVE_INTERVAL = 25 * 1000;
const SESSION_INTERVAL = 75 * 1000;
const USER_ENTROPY_LENGTH = 64;


const http_options = {hostname:"127.0.0.1",port:8000};
const server = serve(http_options);
server_start_time = Date.now();
log.info("server started 127.0.0.1:8000 " + new Date());

await initValidUser(PASSWD_FILE);
await checkAlive();
await houseKeep();

for await (const req of server)
{
    let clientstring:any = ""; 
    /* Get the client ip address and user agent */
    try
    {
        let req_addr:any = req.conn.remoteAddr;
        clientstring = (req_addr.hostname ? req_addr.hostname : " " ) + " " + clientstring; 
        clientstring += req.headers.get("user-agent");
        log.info("Connection from " + clientstring + " " + new Date());
   
    }
    catch(err)
    {
        log.error({message: "cannot get client ip and user agent ", Error: err});
        clientstring = " ";
    }

    if(acceptable(req))
    {
        const { conn, r: bufReader, w: bufWriter, headers } = req;
        acceptWebSocket(
            {
                conn,
                bufReader,
                bufWriter,
                headers,
            }
        )
        .then(
            async (websocket) => 
            {
                return handleWs(websocket, clientstring);
            }
        )
        .catch( 
            async (err) => 
            {
                log.error(err);
                await req.respond({ status: 400 });
            }
        );
    }
    else
    {
        await req.respond({ status:400 });
    }

}

/* read in the users from the password file */
async function initValidUser(password_file:string)
{
    let fileReader = await Deno.open(password_file);

    for await (let line of readLines(fileReader)) 
    {
        let arr = line.split(":");

        if (arr.length === 3 && arr[0].length >= 3)
        {
            passwd_users_list.push(new ValidUser(arr[0], arr[1], arr[2]));
        }
       
    }

    Deno.close(fileReader.rid);

} 


/* Handles the websocket connection */
async function handleWs(sock: WebSocket, clientstring:any)
{
    num_sockets++;
    socket_list.push(sock);

    if(num_sockets > MAX_SOCKETS)
    {
        await sock.close(1000).catch(log.error);
        log.error("Exceeded max sockets limit");
        return;
    }

    log.info("socket connected! " + num_sockets);
    try 
    {
        for await (const ev of sock) 
        {
            if (typeof ev === "string") 
            {
                let msg:string = ev.toString();
                await processMsg(sock, clientstring, msg);
            }
            else if (isWebSocketCloseEvent(ev))
            {
                await cleanUpSocket(sock,null);
            }
            else
            {
                log.info("socket closing non string");
                await cleanUpSocket(sock,null);
            }
        }
    } 
    catch (err) 
    {
        log.error({message: "failed to receive frame: ", Error: err});  
        await cleanUpSocket(sock,null);
    }

}

/* Function to find chat user from given socket */
function findUserFromSocket(sock:WebSocket)
{
    let chatuser:ChatUser|null = null;
                
    for(const [username, user] of users)
    {
        if(user.sock === sock)
        {
            chatuser = user; 
            break;
        }
    }

    return chatuser;

}



/* Clean up socket and its associated chat user */
async function cleanUpSocket(sock:WebSocket, user:ChatUser|null)
{

    let chatuser:ChatUser|null = null;

    if(user !== null)
    {
        chatuser = user;
    }
    else
    {
        chatuser = findUserFromSocket(sock);
    }
    
    if(chatuser !== null)
    {
        let delete_user = chatuser.username; 
        users.delete(delete_user);
        log.info("Removed user from chat users list " + delete_user);
        await sendDisconnectNotice(delete_user);
    }

    num_sockets--;
    if (!sock.isClosed) 
    {
        await sock.close(1000).catch(log.error);
        log.info("socket closing " + num_sockets);
    }

}



/* Process the types of message */
async function processMsg(sock: WebSocket, clientstring:any, msg:string)
{
    let obj;
    try
    {
        obj = JSON.parse(msg);
    }
    catch(err)
    {
        log.error({message: "invalid json : " + clientstring + " : " + new Date(), Error: err});
        await cleanUpSocket(sock,null);
        return;
    }

    if(obj.command === undefined)
    {
        log.error("command not present : " + clientstring + " : " + new Date());
        await cleanUpSocket(sock,null);
        return;
    }

    switch(obj.command)
    {
        case "Login":
            handleUserLogin(clientstring, obj, sock);
            break;

        case  "Offer":
        case "Answer":
        case "Icecandidate":
            relayToPeer(obj);
            break;

        case "Ping":
            handlePing(obj);
            break;
        case "RelayChatMsg":
            handleRelayChatMessage(obj);
            break;
        default:
            log.warning("invalid command from : " + clientstring + " : " + new Date());
            await cleanUpSocket(sock,null);
            break;
    }

}

/* Verify Message from chat users */
function checkMessage(obj:any)
{
    if(obj.from === undefined) return undefined;
    
    let user = users.get(obj.from);
    if(user === undefined) return undefined;

    if(obj.from !== user.username) return undefined;
    
    if(obj.uuid !== user.uuid) return undefined;

    user.lastseen = Date.now();
    return user; 
}


/* Relay chat messages for users who cannot connect Peer to Peer */
async function handleRelayChatMessage(obj:any)
{
    let user = checkMessage(obj);
    if(user === undefined) return;

    log.info("RelayChat message received and processing");

    if(!allow_relay)
    {
        log.warning("Invalid relay request from" + user);
        return;
    }

   let userarr = obj.to;
   let failusers:string[] = [];
  
   for(let i=0; i< userarr.length; i++)
   {
        let dest = users.get(userarr[i]);
        if(dest === undefined) 
        {
            /* Target user could have already disconnected send failure notification */
            failusers.push(userarr[i]); 
            continue; 
        }

        log.info("Relaying to " + dest.username);

        let ret = await sendMessage(
            dest,
            {
                command: "ChatMsg",
                from: user.username,
                msg: obj.msg
            }
        );

        /* To send failure notification */
        if(!ret)
        {
            failusers.push(dest.username);
        }
   }

   if(failusers.length > 0)
   {
        await sendMessage(
            user,
            {
                command: "RelayFail",
                from: failusers,
            }
        );
   }

}


/* Handle Keepalive Ping */
async function handlePing(obj:any)
{
    let user = checkMessage(obj);
    if(user === undefined) return;
    await sendMessage(user, {command: "Pong"});

}

/* Relay to peer webrtc connection */
async function relayToPeer(obj:any)
{
    let source = checkMessage(obj);
    if(source === undefined) return;

    let dest = users.get(obj.to);
    if(dest === undefined)  return; 

    await sendMessage(dest, {
        command: obj.command,
        from: source.username,
        webrtc: obj.webrtc
    });

}


/* Handle chat user login */
async function handleUserLogin(clientstring:any, obj:any, sock: WebSocket)
{
    log.info("login requsted : " + clientstring + " : " + new Date());
    let cmd:Command = {
        command: obj.command,
        username: obj.from,
        password: obj.password
    }

    if (checkLogin(cmd))
    {
        log.info("login success : " + cmd.username + " : " + clientstring + " : " + new Date());
        let user = new ChatUser(cmd.username!, sock);
        let user_entropy = obj.entropy;
      
        if(user_entropy === undefined || user_entropy === "0" || user_entropy.length < USER_ENTROPY_LENGTH)
        {
            log.warning("Invalid entropy from user " + user.username);
            user_entropy = Math.ceil(Math.random() * 1000000000);
        }

        let ran = Math.ceil(Math.random() * 1000000000);
        let sess = user.uuid + clientstring + Date.now().toString() + ran + user_entropy + cmd.username;
        const hash = createHash("sha256");
        hash.update(sess);
        user.uuid = hash.toString();

        users.set(cmd.username!, user);
        await sendMessage(user,  {command: "LoginSuccess", id: user.uuid, username: user.username});
                
        if(allow_relay)
        {/* Tell user that relaying is allow*/
            await sendMessage(user, 
                {
                    command: "RelayOpt",
                    relayopt: "true"
                }
            );
        }

        await sendMessage(user, formatUserList());  

    }
    else
    {
        log.warning("login fail : " + cmd.username + " : " + clientstring + " : " + new Date()); 
    }

}



/* Check for valid user login */
function checkLogin(cmd:Command)
{
    if(cmd.username === undefined || cmd.password === undefined)
    {
        return false; 
    }

    let ui:number;
    let validuser = false;

    for(ui = 0 ; ui < passwd_users_list.length; ui++)
    {
        if(passwd_users_list[ui].username === cmd.username)
        {
            if(!passwd_users_list[ui].locked)
            {
                validuser = true;
                break;
            }

        }
    }

    if(validuser)
    {
        let submit_pass = cmd.password + passwd_users_list[ui].random;
        const hash = createHash("sha256");
        hash.update(submit_pass);
        const hexstring = hash.toString();

        if(hexstring === passwd_users_list[ui].hash)
        {
            passwd_users_list[ui].failed = 0;
            return true;
        }
        else
        {
            passwd_users_list[ui].failed++;
            if (passwd_users_list[ui].failed > MAX_FAILED_LOGIN)
            {
                passwd_users_list[ui].locked = true; 
                log.warning("Account locked : " + cmd.username);
            }
        }

    }

    return false;

}

/* send a message to user */
async function sendMessage (user:ChatUser, obj:any)
{
    let sock: WebSocket = user.sock;
    try
    {
        log.info("sending message to " + user.username);
        sock.send(JSON.stringify(obj));
    }
    catch(err)
    {
        let username = user.username;
        log.error({message: "websocket error : " + username, Error: err});
        await cleanUpSocket(sock, user);
        return false;
    }

    return true;
    
}


/* Send a user disconnection notification */
async function sendDisconnectNotice(disconnect_user:string)
{
    log.info("Sending disconnection notice for " + disconnect_user);
    for(const [username, user] of users)
    {
        await sendMessage(user, 
            {
                command: "Disconnect",
                from: disconnect_user
            }
        );
    }
}


/* format chat users into a object */
function formatUserList()
{
    let arr:string[] = [];
    users.forEach(

        (value, key) => 
        {
            arr.push(key);
        } 

    );

    return {command:"UserList", userlist:arr};

}


/* Check that the websocket connection is still alive */
async function checkAlive()
{
    for(const [username, user] of users)
    {
        let currenttime = Date.now();
        if(currenttime - user.lastseen > SESSION_INTERVAL)
        {
            let expire_user = username;
            log.error("Websocket time out for " + expire_user);
            await cleanUpSocket(user.sock, user);
        }
        
    }

    setTimeout(checkAlive, KEEP_ALIVE_INTERVAL);
}


/* House keeping to check stale sockets and print statistics */
async function houseKeep()
{

    let num_stale_sock = 0;
    let socket_list_length = socket_list.length;
    let to_close_socket: WebSocket[] = [];

    /* Clear sockets that don't belong to chat users */
    for (let i = 0; i < socket_list_length ; i++)
    {
        let sock = socket_list[i];
        let user = findUserFromSocket(sock);

        if(user=== null)
        {  /* Socket doesn't belong to chat users */
            num_stale_sock++;    
            to_close_socket.push(sock);
        }
     
    }

    /* clear socket list */
    socket_list = [];

    for(let i = 0 ; i < to_close_socket.length ; i++)
    {
        let sock = to_close_socket[i];
        if(!sock.isClosed)
        {
            num_sockets--;
            await sock.close(1000).catch(log.error);
        }
    }


    /*
     check for failed logins and locked accounts
    */
   let user_failed_login = 0;
   let user_locked = 0;
   for(let i = 0; i < passwd_users_list.length; i++)
   {
       let valid_user = passwd_users_list[i];
       if(valid_user.failed > 0) { user_failed_login++; }
       if(valid_user.locked) { user_locked++; }
   }

   let server_uptime = Date.now() - server_start_time;
   let currentdate = new Date();

    log.info(" ");
    log.info("-------------------------Statistics------------------------");
    log.info(currentdate); 
    log.info("Server uptime: " + server_uptime);
    log.info("Number of sockets (num_sockets): " + num_sockets);
    log.info("Number of sockets before cleanup (socket_list): " + socket_list_length);
    log.info("Number of stale sockets before cleanup (socket_list): " + num_stale_sock);
    log.info("Number of chat users: " + users.size);
    log.info("Number of accounts with failed login: " + user_failed_login);
    log.info("Number of accounts locked: " + user_locked);
    log.info("------------------------------------------------------------");
    log.info(" ");


    setTimeout(
        houseKeep,
        HOUSE_KEEP_INTERVAL
    );

}