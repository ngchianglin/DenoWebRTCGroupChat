/*
A Simple peer to peer groupchat using webrtc
The backend signaling server uses websocket and Deno

For NAT traversal, it uses google stun server. 
There is no relaying TURN server. The app will not work for clients
that cannot traverse NAT. Most home and small office routers generally
uses NAT scheme that can be traversed. 

A modern and up to date browser like firefox or chrome is needed.

Ng Chiang Lin
Sep 2020

*/


(function()
{

   /* 
    Specifies the websocket URL, make sure you use TLS/SSL
    for security. i.e the url should start with wss:// 

    An example setup can use Nginx as a front end web server and proxy with TLS/SSL
    enabled. The groupchat.html file, groupchat.js and style.css are served 
    from the nginx webserver. 
    
    Nginx also proxies the websocket connections to the backend 
    Deno signaling server that listens on localhost port 8000

   */ 

   const URL = 'wss://nighthour.sg:4430/mygroupchat';

   const STUN_SERVER = {'urls': 'stun:stun.l.google.com:19302'};
   //const STUN_SERVER = {'urls': 'stun:stun.nighthour.sg:443'};
   const PEER_CONNECTION_TIMEOUT = 10000; 
   const MAX_PEER_RETRIES = 2; 
   const MAX_PEER_NOACTIVITY_TIME = 60 * 1000; 
   const MAX_CHAT_HISTORY_SIZE = 250;
   const KEEP_ALIVE_INTERVAL = 25 * 1000;
   const PEER_KEEP_ALIVE_FAIL_THRESHOLD = 2;
   const TOUCH_DISENGAGE_TIME = 5 * 1000;
   const ENTROPY_LENGTH = 32;
   const AES_KEY_LEN = 128;
   const AES_IV_LEN = 12;
   const AES_TYPE = "AES-GCM";


   let socket = null;
   let login_throttle = false;
   let chat_enable = false; 
   let chat_msg_display_enable = false;
   let chat_init_timer = null; 
   let username = "";
   let myid = "";
   let login_success = false; 
   let debug = false;
   let socket_keepalive_enable = true;
   let socket_keep_alive_timer = null;
   let touch_start_time  = 0;
   let chat_history = 0; 
   let activeusers = new Map();
   let allow_relay = false; 
   let secret; 

   window.addEventListener("load", (event) => { initform(); });

   /* An active chat user */
   class ActiveUser
   {
       constructor(username, peerconnection, peerkey)
       {
           this.username = username;
           this.peerconnection = peerconnection;
           this.datachannel = null;
           this.established = false;
           this.keepalivefail = 0;
           this.lastseen = new Date().getTime();
           this.relay = false; 
           this.secret = peerkey;
       }

   }


   /* web form initialzes the chat app */
   function initform() 
   {
        if(location.hash === "#debug") debug = true; 
        
        const btn_login = document.getElementById("login_btn");
        btn_login.addEventListener('click', 
            (event) =>
            {
                login();
            }
        );

   }

   /* Initialize websocket connection to Signal Server */
   function initSocket()
   {
        /*
            WebSocket.readyState 
            0 connecting
            1 open
            2 closing
            3 close
       */

        /* Socket already open */
        if(socket !== null && socket.readyState === 1) return; 
 
        socket = new WebSocket(URL); 
        socket.onmessage = (event) => { processMsg(event); }   

        socket.onerror = (event) =>
        {
            sock_error_msg = "Websocket error cannot send to Signal Server";
            try
            {
                debug_log("websocket onerror " + event); 
                displayChatMessage("", sock_error_msg);
            }
            catch(err)
            {
                debug_log("websocket close error " + err);
                displayChatMessage("", sock_error_msg);
            }
        }

        socket.onclose = (event) => 
        {
            debug_log("websocket closed"); 
            displayChatMessage("", "Signal Server websocket closed !");
        }

   }




   /* Web form handles the user login */
   function login()
   {

        if(login_throttle)  return; 

        const form_login = document.getElementById("login_form");
        let form_username = form_login.username.value;
        let password = form_login.password.value; 

        if (form_username === "" || password === "")
        {
            alert("Username and password cannot be empty!");
            return;
        }

        initSocket();

        let msg_comp = document.getElementById('login_msg');
        msg_comp.innerHTML = "Logging in please wait....";
        
        /* websocket not connected yet */
        if(socket.readyState !== 1)
        {
            setTimeout(
                ()=>{
                    submitLogin(form_username, password);
                    form_username = password = "";
                },
                1000
            );
        }
        else
        {
            submitLogin(form_username, password);
            form_username = password = "";
        }

        /* throttle the login rate to once per 5 second */
        const btn_login = document.getElementById("login_btn");
        btn_login.diabled = true;
        login_throttle = true;

        setTimeout(
            function() { 
                btn_login.diabled = false; 
                login_throttle = false;
                msg_comp.innerText = "";
                if(!login_success) 
                {
                    try
                    {
                        socket.close();
                    }
                    catch(err)
                    {
                        debug_log("Error closing websocket " + err);
                    }
                }
            }, 
            5000
        );

   }


   /* Web form submits the login credentials */
   function submitLogin(username, password)
   {
        let entropy = generateRandom(ENTROPY_LENGTH);
        debug_log("Entropy: " + entropy);
        generateKeySendLogin(username, password, entropy);      
   }


   /* Generate secret key for encrypting message and sends login to signal server */
   async function generateKeySendLogin(username, password, entropy)
   {
        window.crypto.subtle.generateKey(
            {
                name: AES_TYPE,
                length: AES_KEY_LEN,
            },
            true,
            ["encrypt", "decrypt"]
        ).then(

            async (key) => {

                secret = key;
                let secret_arr = await getNumberArrayFromKey(secret);
               
                /* Send login credentials */
                sendSignalMessage(
                    {
                        command:'Login',
                        from: username,
                        password: password,
                        entropy: entropy,
                        secret: secret_arr
                    }
                );
                username = password = "";
                secret_arr = raw_key = raw_key_buf = key = null;
            
            }

        );

   }


   /* Crypto function to get secret key as an array of number */
   async function getNumberArrayFromKey(secret_key)
   {
        let raw_key = await window.crypto.subtle.exportKey("raw", secret_key);
        let raw_key_buf = new Uint8Array(raw_key);
        
        return getNumberArrayFromBytes(raw_key_buf);
   }


   /* Crypto Get number array from byte array */
   function getNumberArrayFromBytes(bytes)
   {
       let num_arr = [];
       for(let i = 0 ; i < bytes.length; i++)
       {
           num_arr.push(bytes[i]);
       }

       return num_arr;
   }


   /* Crypto Get byte array from number array */
   function getByteArrayFromNumbers(numbers)
   {
       let byte_arr = new Uint8Array(numbers.length);
       for(let i = 0; i < numbers.length; i++)
       {
           byte_arr[i] = numbers[i];
       }

       return byte_arr;
   }


    /* Crypto function to convert array of numbers to raw secret key */
    async function getSecretKey(secret_arr)
    {
        let keysize = AES_KEY_LEN / 8;
        let rawkey = new Uint8Array(keysize);
 
        for(let i=0 ; i< secret_arr.length; i++)
        {
            rawkey[i] = secret_arr[i];
        }
 
        let key = null;
        try
        {
             key = await window.crypto.subtle.importKey(
                 "raw",
                 rawkey,
                 AES_TYPE,
                 false,
                 ["encrypt", "decrypt"]
             );
        }
        catch(err)
        {
            debug_log("Error importing key " + err);
        }
 
       return key;
 
    }


    /* Crypto Encrypt chat message */
    async function encryptChatMessage(message)
    {
        let utf8_encoder = new TextEncoder();
        let enc = utf8_encoder.encode(message);
        let iv = window.crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
        let ciphertext = null;

        try
        {
            ciphertext = await window.crypto.subtle.encrypt(
                {
                  name: AES_TYPE,
                  iv: iv
                },
                secret,
                enc
            );
        }
        catch(err)
        {
            debug_log("Failed to encrypt chat message " + err);
            displayChatMessage("", "Failed to encrypt chat message");
        }

        let bytes = new Uint8Array(ciphertext);
        let message_arr = getNumberArrayFromBytes(bytes);
        let iv_arr = getNumberArrayFromBytes(iv);

        return {message:message_arr,iv:iv_arr};

    }


    /* Crypto Decrypt Chat Message */
    async function decryptChatMessage(msg_obj, key)
    {
        let iv_arr = msg_obj.iv;
        let message_arr = msg_obj.message;

        if(iv_arr === undefined || message_arr === undefined)
        {
            debug_log("Cannot decrypt invalid chat message");
            displayChatMessage("", "Cannot decrypt invalid chat message");
            return null;
        }

        let iv = getByteArrayFromNumbers(iv_arr);
        let ciphertext = getByteArrayFromNumbers(message_arr);
        let decrypted = null;

        try
        {
            decrypted = await window.crypto.subtle.decrypt(
                {
                  name: AES_TYPE,
                  iv: iv
                },
                key,
                ciphertext
            );

        }
        catch(err)
        {
            debug_log("Failed to decrypt chat message " + err);
            displayChatMessage("", "Failed to decrypt chat message");
            return null;
        }

        let utf8_decoder = new TextDecoder();
        let decrypted_message = utf8_decoder.decode(decrypted);

        return decrypted_message;

    }


     /* Crypto Generate a random string for more entropy using webcrypto */
   function generateRandom(len)
   {
       let alpha = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'];
       let ran = new Uint8Array(len);
       try
       {
            window.crypto.getRandomValues(ran);
       }
       catch(err)
       {
            debug_log("Error generating random entropy " + err);
            return "0";
       }
      
       let hexstr ="";
       let mask = 0x0f;

       for(let i=0; i< ran.length; i++)
       {
           let hex = "";
           let val = ran[i];
           let index = val & mask;
           hex = alpha[index]; 

           val = val >> 4;
           index = val & mask;
           hex = alpha[index] + hex; 
           hexstr += hex;
       }

       return hexstr;

   }
 

   /* Web UI displays Chat Component upon login Success */
   function showchatComponent()
   {
        /* Hide login component */
        const login_component = document.querySelector(".login-container"); 
        login_component.style.display = "none";

        /* Show chat component */
        const chat_component = document.querySelector(".chat-container");
        chat_component.style.display = "block";
   }


   /* Web UI displays a connected user in the user list*/
   function displayUser(username)
   {
        const user_component = document.querySelector(".ul-container");
        let displayuser = sanitize(username);

        let children = user_component.children;
        for(let i=0; i < children.length; i++)
        {
            let child_div = children[i];
            /* User already shown */
            if(child_div.textContent === displayuser) return;
        
        }

        let user_div = document.createElement('div');
        user_div.setAttribute('class', 'user');
        user_div.textContent=displayuser; 
        
        user_component.appendChild(user_div);
        user_component.scrollTop = user_component.scrollHeight;

   }


   /* Web UI removes a disconnected user in the user list */
   function removeUserDisplay(username)
   {
        const user_component = document.querySelector(".ul-container");
        let displayuser = sanitize(username);
        let child_div = null;

        let children = user_component.children;
        for(let i=0; i < children.length; i++)
        {
            if(children[i].textContent === displayuser)
            {
                child_div = children[i];
                break;
            }
        }

        if(child_div !== null) user_component.removeChild(child_div);
   }


   /* Process the websocket messages */
   function processMsg(event)
   {
        let obj;

        try 
        {
            obj = JSON.parse(event.data);
        }
        catch(err)
        {
            debug_log("Json parsing error " + err);
            return;
        }


        switch(obj.command)
        {
            case "LoginSuccess":
                loginSuccess(obj);
                break;

            case "UserList":
                initialize_peers(obj.userlist);
                break;

            case "Offer":
                acceptPeerOffer(obj);
                break;

            case "Answer":
                acceptPeerAnswer(obj);
                break;

            case "Icecandidate":
                acceptPeerIce(obj);
                break;
            case "RelayOpt":
                setRelayOption(obj);
                break;
            case "ChatMsg":
                handleRelayChatMessage(obj);
                break;
            case "RelayFail":
                handleRelayFail(obj);
                break;
            case "Disconnect":
                handleDisconnectNotice(obj);
                break;
            case "Pong":
                debug_log("keepalive reply from signal server");
                break;

            default:
                debug_log("Unknown websocket command");
                break;
        }

   }


   /* Function to handle Disconnection notice for websocket relaying users*/
   function handleDisconnectNotice(msg_obj)
   {
        let disconnect_user = msg_obj.from;
        let peer = activeusers.get(disconnect_user);
        if(peer === undefined) return;

        if(peer.relay)
        {
            peerDisconnected(disconnect_user);
        }

   }


   /* Function to handle relay failure notification */
   function handleRelayFail(msg_obj)
   {
        let failusers = msg_obj.from;

        if(failusers.length <= 0)
        {
            debug_log("Invalid fail notification received");
            return;
        }


        for(let i=0; i< failusers.length; i++)
        {
            let peername = failusers[i];
            let peer = activeusers.get(peername);
    
            if(peer === undefined) 
            {
                displayChatMessage("", "Receive message from unknown peer " + peername);
                debug_log("Receive message from unknown peer " + peername);
                continue;
            }
    
            displayChatMessage("", "Failed to relay message to " + peername);
            peerDisconnected(peername);

        }

   }


   /* Relayed Chat Message received. Display it */
   async function handleRelayChatMessage(msg_obj)
   {
        let peername = msg_obj.from;
        let peer = activeusers.get(peername);

        if(peer === undefined) 
        {
            displayChatMessage("", "Receive message from unknown peer " + peername);
            debug_log("Receive message from unknown peer " + peername);
            return;
        }

        let decrypted = await decryptChatMessage(msg_obj.msg, peer.secret);
        if(decrypted === null) decrypted = "null";

        displayChatMessage(msg_obj.from, decrypted);
   }


   /* 
      Set whether the signal server allow relaying of chat messages if 
      peer to peer connection cannot be established
   */
   function setRelayOption(obj)
   {
       if(obj.relayopt === "true")
       {
           allow_relay = true;
       }
       else
       {
           allow_relay = false;
       }

   }


   /* Handles the login success message from signal server */
   function loginSuccess(obj)
   {
        myid = obj.id;
        username = obj.username;
        debug_log("My id set " + username);
        
        login_success = true;
        chat_msg_display_enable = true;
        showchatComponent();
        displayUser(username);
        displayChatMessage("", "Welcome 欢迎, " + username);
        displayChatMessage("", "To exit chat, close the browser window or tab. Reload the page to log out.");
        displayChatMessage("", "Control B to disengage signal server. For mobile device, touch and hold chat "+
                                "message screen for 5 seconds and then release.");
        chat_init_msg(1);
        socketKeepAlive();
   }


   /* Initialize connections to peers from userlist */
   async function initialize_peers(userlist)
   {
        let arr = userlist; 
        let num_peer = arr.length - 1; 
        let message = "";

        if (num_peer === 0)
        {
            message = "0 peer. Waiting for others to connect...";
        }
        else
        {
            message = "Connecting to " + num_peer + (num_peer > 1 ? " peers" : " peer");
        }

        displayChatMessage("", message);

        for(let i=0; i < arr.length; i++)
        {
            let obj = arr[i];
            let peername = obj.user;
            let secret_arr = obj.secret;
            
            if(peername === undefined || secret_arr === undefined || peername === username) continue;

            let peerkey = await getSecretKey(secret_arr);
            if(peerkey === null)
            {
                debug_log("Invalid key from peer " + peername + " skipping");
                continue;
            }

            connectToPeer(peername, peerkey);
            /* Fall back to relaying if webrtc fails */
            setTimeout( 
                ()=>{
                    checkPeerConnectionStatus(peername, MAX_PEER_RETRIES, true);
                },
                PEER_CONNECTION_TIMEOUT
            );
        }

   }


  

   /* Accepts Peer webrtc ICE candidate */
   async function acceptPeerIce(ice_obj)
   {
        debug_log("Received ICE from " + ice_obj.from);
        let peername = ice_obj.from; 
        let peer = activeusers.get(peername);
        if(peer === undefined) 
        {
            displayChatMessage("", "Serious error for peer: " + peername);
            debug_log("cannot find peer in activeusers Peer ICE " + peername);
            return; 
        }

        let peerConnection = peer.peerconnection; 
        try 
        {
            await peerConnection.addIceCandidate(ice_obj.webrtc);
        } 
        catch (err) 
        {
            debug_log("Error adding received ice candidate from " + peername + " " + err);
            return;
        }

        debug_log("ICE accepted");

   }


   /* Accepts Peer webrtc connection answer */
   async function acceptPeerAnswer(answer_obj)
   {
       debug_log("Received Answer from " + answer_obj.from);

       let peername = answer_obj.from; 
       let peer = activeusers.get(peername);
       if(peer === undefined) 
       { 
           displayChatMessage("", "Serious error for peer: " + peername);
           debug_log("cannot find peer in activeusers Peer Answer " + peername);
           return; 
       }

       let peerConnection = peer.peerconnection; 

       const remoteDesc = new RTCSessionDescription(answer_obj.webrtc);
       await peerConnection.setRemoteDescription(remoteDesc);

       debug_log("Answer accepted");

   }


   /* Accepts Peer webrtc connection offer */
   async function acceptPeerOffer(offer_obj)
   {
        debug_log("Received Offer from " + offer_obj.from);
        let peername = offer_obj.from; 

        const configuration = {'iceServers': [STUN_SERVER]};
        const peerConnection = new RTCPeerConnection(configuration);

        let secret_arr = offer_obj.secret;
        let peerkey = await getSecretKey(secret_arr);
        if(peerkey === null)
        {
            debug_log("Invalid key from peer " + peername + " rejecting offer");
            return;
        }

        peer = new ActiveUser(peername, peerConnection, peerkey);
        activeusers.set(peername, peer);

        peerConnection.ondatachannel = (event) => 
        { 
            debug_log("Data channel created " + peername);
            peer.datachannel = event.channel;
            setDataChannelEventHandler(peer.datachannel, peername);
        };
        
        setIceEventHandler(peerConnection, peername);

        peerConnection.setRemoteDescription(new RTCSessionDescription(offer_obj.webrtc));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);

        debug_log("Sending answer to peer " + peername);

        sendSignalMessage(
            {
                command: "Answer",
                from: username,
                uuid: myid,
                to: peername,
                webrtc: answer
            }
        );

        /* Fallback to relaying if webrtc fails */
        setTimeout( 
            ()=>{
                checkPeerConnectionStatus(peername, MAX_PEER_RETRIES, false);
            },
            PEER_CONNECTION_TIMEOUT
        );

   }


   /* Connects to Peers Using WebRTC Datachannel */
   async function connectToPeer(peername, peerkey)
   {
        debug_log("Connecting to " + peername);
        displayChatMessage("", "Connecting to " + peername);

        const configuration = {'iceServers': [STUN_SERVER]};
        const peerConnection = new RTCPeerConnection(configuration);
        const dataChannel = peerConnection.createDataChannel(peername);

        peer = new ActiveUser(peername, peerConnection, peerkey);
        peer.datachannel = dataChannel;
        activeusers.set(peername, peer);

        setDataChannelEventHandler(peer.datachannel, peername);
        setIceEventHandler(peerConnection, peername);

        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);

        /* Get our own secret key and send this to the peer */
        let secret_arr = await getNumberArrayFromKey(secret);

        debug_log("Sending offer to " + peername);

        sendSignalMessage(
            {
                command: "Offer",
                from: username,
                uuid: myid,
                to: peername,
                webrtc: offer,
                secret: secret_arr
            }
        );

   }
   

   /* Set the webrtc datachannel event handler */
   function setDataChannelEventHandler(datachannel, peername)
   {
        datachannel.onopen = (event) => 
        {
            debug_log("Data channel opened to peer " + peername);
            let peer = activeusers.get(peername);
            if(peer === "undefined") 
            { 
                displayChatMessage("", "Serious error for peer: " + peername);
                debug_log("Cannot get peer from activeusers for datachannel onopen " + peername);
                return;
            } 

            peerConnectionSuccess(peer, true, false);

        }

        datachannel.onmessage = (event) => 
        {
            debug_log("Data channel received message " + event.data);
            receiveChatMessage(event.data);
        }

        datachannel.onclose = (event) =>
        {
            let peer = activeusers.get(peername);
            if(peer === "undefined" || !peer.established) return;

            peerDisconnected(peer.username);

        }

        datachannel.onerror = (event) =>
        {
            let peer = activeusers.get(peername);
            if(peer === "undefined" || !peer.established) return;

            debug_log("Network error " + peername);
            datachannel.close();
        }

   }

  

   /* Set webrtc Icecandidate event handler */
   function setIceEventHandler(connection, peername)
   {
        connection.addEventListener
        (
            'icecandidate', 
            (event) => {
                if (event.candidate)
                {
                    debug_log("sending icecandidate to " + peername);
                    sendSignalMessage(
                        {
                            command: "Icecandidate",
                            from: username,
                            uuid: myid,
                            to: peername,
                            webrtc: event.candidate

                        }
                    );
                }
            }
        );
   }


   /* 
     Check peer connection status. 
     If relaying is enabled on the server, a peer can fallback to relaying if webrtc fails.

     The display_retry_flag should be set to true for the peer starting the connection to other peers
     For peers receving connections, the display_retry_flag should be set to false to avoid unnecessary
     status messages. 
   
   */
   function checkPeerConnectionStatus(peername, retries, display_retry_flag)
   {         
       peer = activeusers.get(peername);
       if(peer === undefined) 
       {
           if(display_retry_flag)
           {
               displayChatMessage("", "WebRtc connection failed for peer: " + peername);
           }
           return;
       }

       if(retries === 0)
       {
           if(allow_relay)
           {/* relaying is allowed by server */
               peerConnectionSuccess(peer, false, true);
           }
           else
           {
               displayChatMessage("", "WebRtc connection failed for peer: " + peername);
               activeusers.delete(peername);
           }
           return; 
       }

       /*
         RTCDataChannel.readyState
            open
            connecting
            closed
            closing
       */

       if(peer.datachannel !== null)
       {
            switch(peer.datachannel.readyState)
            {
                case "connecting":
    
                    if(display_retry_flag)
                    {
                        displayChatMessage("", "Trying to connect to peer: " + peername);
                    }
    
                    setTimeout( 
                        ()=>{
                            checkPeerConnectionStatus(peername, retries -1,display_retry_flag);
                        },
                        PEER_CONNECTION_TIMEOUT
                    );
                    break;
    
                case "closed":
                case "closing":
    
                    if(allow_relay === true)
                    {
                        peerConnectionSuccess(peer, false, true);
                    }
                    else
                    {
                        if(display_retry_flag)
                        {
                            displayChatMessage("", "WebRtc connection failed for peer: " + peername);
                        }
                        activeusers.delete(peername);
                    }
                    break;
                default:
                    break;
    
            }
       }
       else
       {
            setTimeout( 
                ()=>{
                    checkPeerConnectionStatus(peername, retries -1,display_retry_flag);
                },
                PEER_CONNECTION_TIMEOUT
            );
       }

   }


   /*Helper function to notify and remove chat user who disconnects */
   function peerDisconnected(disconnect_user)
   {
        displayChatMessage("", disconnect_user + " disconnected");
        debug_log(disconnect_user + " disconnected");
        removeUserDisplay(disconnect_user);
        activeusers.delete(disconnect_user);
   }
   

    /* 
     Helper function notify and display that a chat usser has connected successfully
     whether by webrtc or by relaying
   */
  function peerConnectionSuccess(peer, webrtc_established, relay_established)
  {

      let peername = peer.username;

      peer.established = webrtc_established; 
      peer.relay = relay_established;
      displayUser(peername);
      displayChatMessage("", peername + " connected");

      if(relay_established)
      {
            displayChatMessage("", "Relaying enabled for peer: " + peername);
      }

      debug_log(peername + " connected webrtc: " + peer.established + " relay: " + peer.relay);

      if(!chat_enable) enableChat();

  }


   /* Receive a webrtc chat message and display it */
   async function receiveChatMessage(message)
   {
       let msg_obj = null;

       try
       {
           msg_obj = JSON.parse(message);
       }
       catch(err)
       {
            debug_log("Json parsing error " + err);
            return;
       }

       if(msg_obj === null || msg_obj.from === undefined || msg_obj.msg === undefined)
       {
           return; 
       }

       let peername = msg_obj.from;
       let peer = activeusers.get(peername);

       if(peer === undefined) 
       {
           displayChatMessage("", "Receive message from unknown peer " + peername);
           debug_log("Receive message from unknown peer " + peername);
           return;
       }

       if(msg_obj.keepalive)
       {
           debug_log("Keepalive from " + peername);
           /* update peer last activity time */
           peer.lastseen = Date.now();
           return;
       }

       if(msg_obj.system)
       {    /* special system message */
            debug_log("system message from " + peername);
            peer.lastseen = Date.now();
            displayChatMessage("", "[" +  peername + "] " + msg_obj.system);
            return;
       }

       /* update peer last activity time */
       peer.lastseen = Date.now();

       let decrypted = await decryptChatMessage(msg_obj.msg, peer.secret);
       if(decrypted === null) decrypted = "null";

       displayChatMessage(msg_obj.from, decrypted);

   }


   /* Send a chat message to all peers */
   async function sendChatMessage()
   {
       debug_log("Sending chat message");
       let chat_form = document.getElementById("chat_message_form");
       let message = chat_form.inputmessage.value; 

       let msg_obj = await encryptChatMessage(message);

       let json = JSON.stringify(
           {
               from: username,
               msg: msg_obj
           }
       );

       let relay_peer = []; 
       
       if(message.length > 0)
       {
           displayChatMessage(username, message);
           activeusers.forEach(
               (peer, peername)=>
               {
                   if(peer.relay)
                   { /* Relaying required for peer */
                        relay_peer.push(peername);
                   }
                   else if(peer.established)
                   {
                        if(!transmitMessage(peer, json))
                        {
                            displayChatMessage("", "Error sending message to " + peername);
                        }
                   }
               }
           );

          if(relay_peer.length > 0) sendMessageRelayPeer(relay_peer, msg_obj);

       } 

       chat_form.reset();
    
    }


    /* Send chat message for peers that require relaying */
    function sendMessageRelayPeer(relay_peer, message)
    {
        if(relay_peer.length === 0) return; 
        debug_log("Relaying chat message");

        sendSignalMessage(
            {
                command:"RelayChatMsg",
                from: username,
                uuid: myid,
                to: relay_peer,
                msg: message
            }
        );
    }


   /* Transmist message over webrtc datachannel */
   function transmitMessage(peer, message)
   {

        if(!peer.established) return true; 

        let peername = peer.username;
   
        if (peer.datachannel.readyState === "open")
        {
            try
            {
                peer.datachannel.send(message); 
            }
            catch(err)
            {
                debug_log("Error sending msg to peer " + peername + " " + err);
                peer.datachannel.close();
                return false;

            }
        }
        else if(peer.datachannel.readyState === "closing"  
                || peer.datachannel.readyState === "closed")
        {
            debug_log("Error sending msg to peer " + peername);
            return false;
        }

        return true;
      
   }


   /* Web UI enables chat once a peer has connected */
   function enableChat()
   {
        chat_enable = true;

        if(chat_init_timer !== null)
        {
            clearTimeout(chat_init_timer);
            chat_init_timer = null;
        }

        let chat_msg_submit_btn = document.getElementById("send_chatmsg_btn");
        chat_msg_submit_btn.addEventListener('click', sendChatMessage);

        document.addEventListener('keydown', detectDisengageKey);

        /* for mobile device set up touch for 5 second to disengage signal server */
        let message_component = document.querySelector(".msg-container");

        message_component.addEventListener('touchstart', 
            (event)=>{ detectDisengageMobile(event, "touchstart"); } 
        );

        message_component.addEventListener('touchend', 
            (event)=>{ detectDisengageMobile(event, "touchend"); } 
       );


        clearTextArea();
        peersKeepAlive();
   }


   /* Web form for mobile detect touch on message display for 5 second to disengage signal server */
   function detectDisengageMobile(event, str)
   {
       if(str === "touchstart")
       {
           touch_start_time = Date.now();
       }


       if(str === "touchend")
       {
           let currenttime = Date.now();
           /* touch for 5 second or more */
           if(currenttime - touch_start_time > TOUCH_DISENGAGE_TIME)
           {
                disengageSignalServer();
           }

       }

       return true;
   }


   /* Web form detects the ctrl-b for disengaging signal server */
   function detectDisengageKey(event)
   {
        if(event.ctrlKey && event.key === "b")
        {
            debug_log("Disengage key detected");
            disengageSignalServer();
            event.preventDefault();
            return false;
        }

        return true; 
   }



   /* 
      Disable connection to Signal server to form a private webrtc peer to peer group 
      All chat users that rely on relaying will be disconnected.
   */
   function disengageSignalServer()
   {

        socket_keepalive_enable=false;

        if(socket_keep_alive_timer !== null)
        {
            clearTimeout(socket_keep_alive_timer);
            socket_keep_alive_timer = null;
        }

        if(socket.readyState === 1)
        {
            try
            {
                socket.close();
            }
            catch(err)
            {
                debug_log("Disengage signal server error closing socket " + err);
            }
        }

        let json = JSON.stringify(
            {
                from: username,
                msg: "",
                system: "Disengage from Signal Server"
            }
        );

        displayChatMessage("", "Disengage from Signal Server");

        let to_delete = [];

        activeusers.forEach(
            (peer, peername)=>
            {
                if(peer.established)
                {
                    debug_log("Sending disengage siganl server msg to "+ peername);
                    if(!transmitMessage(peer, json))
                    {
                        displayChatMessage("", "Error sending system message to " + peername);
                    }
                }
                else
                {
                    to_delete.push(peername);
                }
            }
        );

        /* remove peers that rely on websocket relaying */
        for(let i=0; i< to_delete.length;i++)
        {
            let disconnect_user = to_delete[i];
            peerDisconnected(disconnect_user);
        }

   }


   /* Keep alive for websocket to Signal Server*/
   function socketKeepAlive()
   {
       if(!socket_keepalive_enable) return;

        debug_log("Sending websocket keepalive");
        sendSignalMessage(
            { 
                command: "Ping",
                from: username,
                uuid: myid
            }
        );

       socket_keep_alive_timer = setTimeout(socketKeepAlive, KEEP_ALIVE_INTERVAL);
   }


   /* Keep alive for webrtc peers */
   function peersKeepAlive()
   {
        let json = JSON.stringify(
            {
                from: username,
                msg: "",
                keepalive: "ping"
            }
        );

        let todelete = [];
        
        activeusers.forEach(
            (peer, peername) =>
            {
                if(peer.established)
                {
                    debug_log("sending keepalive to " + peername);
                    if(!transmitMessage(peer, json))
                    {
                        peer.keepalivefail++;
                        debug_log("Error sending keepalive to peer " + peername);
                    }
    
                    let currenttime = Date.now();
                    if(currenttime - peer.lastseen > MAX_PEER_NOACTIVITY_TIME)
                    {
                        peer.keepalivefail = PEER_KEEP_ALIVE_FAIL_THRESHOLD + 1; 
                    }
    
                    if(peer.keepalivefail >= PEER_KEEP_ALIVE_FAIL_THRESHOLD)
                    {  /* More than PEER_KEEP_ALIVE_FAIL_THRESHOLD keepalive failures for peer. 
                        Need to remove peer manually */
                        debug_log("More than " + PEER_KEEP_ALIVE_FAIL_THRESHOLD + 
                                  " keepalive fail, remove peer manually " + peername);
                        todelete.push(peername);
                    }
                }

            }
        );

        for(let i=0; i < todelete.length; i++)
        {
            let disconnect_user = todelete[i];
            peerDisconnected(disconnect_user);
        }

        setTimeout(peersKeepAlive, KEEP_ALIVE_INTERVAL);
   }


   /* Web UI clears the chat text area */
   function clearTextArea()
   {
        let chat_form = document.getElementById("chat_message_form");
        chat_form.reset();
   }


   /* Web UI displays Chat Message */
   function displayChatMessage(user, message)
   {
        if(!chat_msg_display_enable) return;
        
        const message_component = document.querySelector(".msg-container");
        
        let msg_div = document.createElement('div');
        msg_div.setAttribute('class', 'msg'); 

        let sanitize_user = sanitize(user);
        let chat_user = document.createElement('span');
        chat_user.setAttribute('class','msguser');
        chat_user.innerHTML = sanitize_user;

        let chat_divider = document.createElement('span');
        chat_divider.textContent = ": ";

        let sanitize_msg = sanitize(message);
        let chat_msg = document.createElement('span');
        chat_msg.innerHTML= sanitize_msg;

        msg_div.appendChild(chat_user);
        msg_div.appendChild(chat_divider);
        msg_div.appendChild(chat_msg);

        if(chat_history >= MAX_CHAT_HISTORY_SIZE)
        {
            message_component.removeChild(message_component.firstChild);
        }
        else
        {
            chat_history++;
        }

        message_component.appendChild(msg_div);  
        message_component.scrollTop = message_component.scrollHeight;

   }


   /* Web UI chat initialization message */
   function chat_init_msg(count)
   {
        const chatform_component = document.getElementById("chat_message_form");
        let init_message = "Please wait. Initialing peer to peer connection ... " + count; 
       
        chatform_component.inputmessage.value = init_message; 
        count++;

        if(!chat_enable)
        {
            chat_init_timer = setTimeout
            (
                function()
                {
                    chat_init_msg(count);
                },
                1000
            );
        }

   }


   /* Send Websocket Signal Message  */
   function sendSignalMessage(obj)
   {
       /* websocket is not open */
       if(socket.readyState !== 1 )
       {
            displayChatMessage("", "Websocket error cannot send to Signal Server");
            debug_log("Websocket error ");
            return;
       }

       try
       {
            socket.send(JSON.stringify(obj));
       }
       catch(err)
       {
            displayChatMessage("", "Websocket error cannot send to Signal Server");
            debug_log("Websocket error " + err);
       }

   }


   /* Sanitize Msg for inclusion into HTML element Owasp xss prevention cheatsheet rule 1 */
   function sanitize(untrusted)
   {
        let sanitized = ""
        sanitized = untrusted.replace(/&/g, "&amp;");
        sanitized = sanitized.replace(/</g, "&lt;");
        sanitized = sanitized.replace(/>/g, "&gt;");
        sanitized = sanitized.replace(/"/g, "&quot;");
        sanitized = sanitized.replace(/'/g, "&#x27;");
        sanitized = sanitized.replace(/\//g, "&#x2F;");
        
        return sanitized;
   }

   
   /* Log debug messages to console */
   function debug_log(msg)
   {
       if(debug)
       {
            console.log(msg);
       }
   }


})();