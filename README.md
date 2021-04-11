# DenoWebRTCGroupChat
A Simple Group Chat application using webrtc datachannel 


## Introduction
This is a simple html 5 peer to peer group chat application using webrtc datachannel. 
The signaling server runs on [Deno](https://deno.land/), a secure runtime for javascript and typescript.
There are no third party modules dependency for the chat application, it is pure html5, a stylesheet and a javascript file. 
The signaling server only uses the Deno standard library. 

The chat application connects to the Deno signaling server through websocket for peers discovery and exchange of webrtc signaling information. 
After a peer to peer webrtc datachannel is established, the chat messages are sent directly through webrtc datachannel and does not pass through the
signaling server. For NAT traversal, the public google stun server is used. 

If there are firewalls or the NAT types that cannot be traversed and the peer to peer webrtc datachannel fails to be established; the chat application 
falls back to relaying messages through the signal server. 

## Screenshots

**GroupChat Login Page**

![Group chat login page](https://github.com/ngchianglin/DenoWebRTCGroupChat/blob/main/image/groupchat-login.png)

**GroupChat Chat Screen**

![Chat Screen](https://github.com/ngchianglin/DenoWebRTCGroupChat/blob/main/image/groupchat.png)


## Requirements
* The latest version of Deno runtime is required from [https://deno.land/](https://deno.land/)
* Deno standard library which will be downloaded automatically when the signal server is executed for the first time. 
* A web and proxy server like Nginx with TLS/SSL enabled. 
* Latest version of firefox, chromium or chrome browser. 
* Linux OS such as debian, ubuntu, redhat etc...for running the signaling server.  


## Installation and Deployment

In the public directory are 3 files, groupchat.html, style.css and groupchat.js. These 3 are the chat client application and they can served from a webserver
like Nginx. Use TLS/SSL when serving out these files. 
You will need to modify the websocket URL in the groupchat.js file to your own specific URL. 

The signalserver directory contains 2 files. groupchat-server.ts and pass-util.ts. groupchat-server.ts is the signaling server. 
It is configured to listen on localhost port 8000 for websocket connections. Nginx can be configured to proxy websocket connections to the signaling server.
Use TLS/SSL for proxying. 

    deno run --allow-net --allow-read=./pass/passwd,/dev/urandom groupchat-server.ts 2>&1 > chatserver.log &

The pass-util.ts is a utility to create chat accounts. The accounts are stored in a passwd file inside a pass directory relative to where you run 
the pass-util.ts. The pass directory needs to be created manually.

    deno run --allow-write=./ --allow-read=./ pass-util.ts  [mychataccount]



## Further Details
Refer to
[https://nighthour.sg/articles/2020/building-a-peer-to-peer-groupchat-using-deno-and-webrtc.html](https://nighthour.sg/articles/2020/building-a-peer-to-peer-groupchat-using-deno-and-webrtc.html)
for more details on the implementation and how it can be deployed.

## Source signature
Gpg Signed commits are used for committing the source files.

> Look at the repository commits tab for the verified label for each commit, or refer to [https://www.nighthour.sg/git-gpg.html](https://www.nighthour.sg/git-gpg.html) for instructions on verifying the git commit.
>
> A userful link on how to verify gpg signature is available at [https://github.com/blog/2144-gpg-signature-verification](https://github.com/blog/2144-gpg-signature-verification)
