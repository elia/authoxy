/*
 *  NTLM.c
 *  Authoxy
 *
 *  Created by Heath Raftery on Fri Jan 2 2004.
 *  Copyright (c) 2004 HRSoftWorks. All rights reserved.
 *
 */

#include "AuthoxyDaemon.h"


//**************************************************************************
//	establishNTLMAuthentication(int clientConnection, int serverSocket, char logging)
//
//	authenticate to the proxy using the NTLM scheme, so the client is free to continue
//  the method is unofficially documented in several places now, but the main reference
//  for this implementation was this:
//  http://davenport.sourceforge.net/ntlm.html#ntlmHttpAuthentication
//
//**************************************************************************
struct sharedData //TODO: make a real structure
{
  char bStep2;
  char key1[40];
  char bStep4;
  char key2[40];
  char bServerConnectionReestablished;
  int  serverSocket;
};

int establishNTLMAuthentication(int clientConnection, int serverSocket, char logging)
{
  //first, set up a shared memory space
  key_t shmKey;
  int shmID;
  struct sharedData *shmData;
  FILE *f = fopen("/tmp/authoxydThreadStuff", "w");  //TODO: we might have to make this unique to the thread
  fclose(f);
  if((shmKey = ftok("/tmp/authoxydThreadStuff", 'A')) == -1)//TODO: or just make 'A' unique
  {
    syslog(LOG_ERR, "Fatal Error: unable to get a key for shared memory");
    close(clientConnection);
    close(serverSocket);
    return 1;
  }
  if((shmID = shmget(shmKey, 1024, 0644 | IPC_CREAT)) == -1)
  {
    syslog(LOG_ERR, "Fatal Error: unable to create shared memory");
    close(clientConnection);
    close(serverSocket);
    return 1;    
  }
  if((shmData = shmat(shmID, (void *)0, 0)) == (struct sharedData*)(-1))
  {
    syslog(LOG_ERR, "Fatal Error: unable to connect to shared memory");
    close(clientConnection);
    close(serverSocket);
    return 1;    
  }
  
  shmData->bStep2 = 0;
  shmData->bStep4 = 0;
  shmData->bServerConnectionReestablished = 0;
  
  syslog(LOG_INFO, "Ready to NTLM!");
  
  //okay, we're going to have to break into two processes to handle both ends of the connection, client->proxy and proxy->client
  pid_t pid;
  switch(pid = fork())			//spawn a new process to handle the request
  {
    case -1:						//trouble!!
      syslog(LOG_ERR, "Fatal Error: Unable to create new process. Errno: %m");
      close(clientConnection);
      exit(1);
      
    case 0:							//the child - client->server
      if(establishNTLMAuthenticationClientSide(clientConnection, serverSocket, logging))
      {
        close(clientConnection);
        close(serverSocket);
        exit(1);        
      }
      else
        exit(0);

    default:                        //the parent - server->client
      ; //wtf?? TODO: figure out why the hell a semicolon is required here.
      syslog(LOG_INFO, "I am the server side!");
      int recvBufSize, responseSize=0;
      char listenBuf[INCOMING_BUF_SIZE+1], *responseBuf=NULL;
      /*****Step 2 - Proxy returns a 401 Unauthorised to the client*****/
      while((recvBufSize = recv(serverSocket, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)
      {
        syslog(LOG_INFO, "Entering Step 2");
        
        if(responseBuf)
        {
          char *tempBuf = (char*)malloc(responseSize);
          bufcpy(tempBuf, responseBuf, responseSize);
          free(responseBuf);
          responseBuf = (char*)malloc(responseSize+recvBufSize);
          bufcpy(responseBuf, tempBuf, responseSize);
          free(tempBuf);
        }
        else
          responseBuf = (char*)malloc(recvBufSize);
        
        bufcat(responseBuf, responseSize, listenBuf, recvBufSize);
        responseSize+=recvBufSize;
      }
      if(recvBufSize<0)
      {
        if(logging)
          syslog(LOG_INFO, "Server closed ungracefully in NTLM authentication Step 2. Killing session processes. Errno: %m.");
        kill(pid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      
      if(strncmp(responseBuf, "HTTP/1.1 401", 12) != 0)
      {
        if(logging)
          syslog(LOG_ERR, "Unexpected server response in NTLM authentication Step 2. Giving up.");
        kill(pid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      
      //otherwise, step 2 is complete
      syslog(LOG_INFO, "Step 2 is complete");
      //shmData->bStep2 = 1;
      //using signals instead of polling for shared memory changes now
      if(kill(pid, SIGCONT)<0)
      {
        syslog(LOG_ERR, "Failed to send continue signal in Step 2. Errno: %m");
        return 1;
      }
      
      //our connection should have been broken by the server, so this parent is going to die now, and let the new child of the child pick up the act.
      free(responseBuf);
  }
      //now we have to reconnect to the server
//      while(!shmData->bServerConnectionReestablished)
//        ;
      //infinite loops are full ghey, let try a stop signal instead. The stop will be cancelled with a continue from the other process.
      if(raise(SIGSTOP)<0)
      {
        syslog(LOG_ERR, "Failed to send stop signal in Step 3. Errno: %m.");
        return 1;
      }
        
      serverSocket = shmData->serverSocket;
      free(responseBuf);
      responseBuf=NULL;
      //and start listening again
      syslog(LOG_INFO, "Entering Step 4");
      /*****Step 4 - Proxy returns another 401 Unauthorised to the client*****/
      while((recvBufSize = recv(serverSocket, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)
      {
        if(responseBuf)
        {
          char *tempBuf = (char*)malloc(responseSize);
          bufcpy(tempBuf, responseBuf, responseSize);
          free(responseBuf);
          responseBuf = (char*)malloc(responseSize+recvBufSize);
          bufcpy(responseBuf, tempBuf, responseSize);
          free(tempBuf);
        }
        else
          responseBuf = (char*)malloc(recvBufSize);
        
        bufcat(responseBuf, responseSize, listenBuf, recvBufSize);
        char endOfResponse = 0;
        int i;
        for(i = responseSize<4 ? 0 : responseSize-4; i<responseSize+recvBufSize-3; i++)
        {
          if(responseBuf[i]==CR && responseBuf[i+1]==LF && responseBuf[i+2]==CR && responseBuf[i+3]==LF)
          {
            endOfResponse = 1;
            break;
          }
        }
        responseSize+=recvBufSize;
        
        if(endOfResponse)
          break;
      }
      if(recvBufSize<0)
      {
        if(logging)
          syslog(LOG_INFO, "Server closed ungracefully in NTLM authentication Step 4. Killing session processes. Errno: %m.");
        kill(pid, SIGKILL);
        free(responseBuf);
        exit(EXIT_FAILURE);
      }
        
      if(strncmp(responseBuf, "HTTP/1.1 401", 12) != 0)
      {
        if(logging)
          syslog(LOG_ERR, "Unexpected server response in NTLM authentication Step 4. Giving up.");
        kill(pid, SIGKILL);
        free(responseBuf);
        exit(EXIT_FAILURE);
      }

      //otherwise, step 4 is complete
      strcpy(shmData->key1, "Key One"); //TODO: of course, the key will be extracted from the server's response
//      shmData->bStep4 = 1;
      //using signals instead of polling for shared memory changes now
      if(kill(pid, SIGCONT)<0)
      {
        syslog(LOG_ERR, "Failed to send continue signal in Step 4. Errno: %m");
        return 1;
      }
        
      //hopefully at this stage, the client will send the final authentication header, and the server will respond with the originally requested data
      //this stage of the communication will be handled by the regular conduct* functions.
      free(responseBuf);
  }
  return 0;
}

//**************************************************************************
//	establishNTLMAuthenticationClientSide(void)
//
//	called by establishNTLMAuthentication() to handle the child process
//
//**************************************************************************
int establishNTLMAuthenticationClientSide(int clientConnection, int serverSocket, char logging)
{
  pid_t ppid = getppid();
  //connect to the shared memory data structure
  key_t shmKey;
  int shmID;
  struct sharedData *shmData;
  FILE *f = fopen("/tmp/authoxydThreadStuff", "w");  //TODO: we might have to make this unique to the thread
  fclose(f);
  if((shmKey = ftok("/tmp/authoxydThreadStuff", 'A')) == -1)//TODO: or just make 'A' unique
  {
    syslog(LOG_ERR, "Fatal Error: unable to get a key for shared memory");
    return 1;
  }
  if((shmID = shmget(shmKey, 1024, 0)) == -1)
  {
    syslog(LOG_ERR, "Fatal Error: unable to connect to shared memory");
    return 1;    
  }
  if((shmData = shmat(shmID, (void *)0, 0)) == (struct sharedData*)(-1))
  {
    syslog(LOG_ERR, "Fatal Error: unable to connect to shared memory");
    return 1;    
  }

 
  syslog(LOG_INFO, "I am the client side!");
  
  int recvBufSize, requestSize=0;
  char listenBuf[INCOMING_BUF_SIZE+1], *requestBuf=NULL;
  syslog(LOG_INFO, "Entering Step 1");
  /*****Step 1 - Client sends regular, unauthenticated request to proxy*****/
  while((recvBufSize = recv(clientConnection, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)  //retrieve the data on the listen socket
  {
    int bytesSent=0;
    while(bytesSent<recvBufSize)
    {
      if((bytesSent += send(serverSocket, &listenBuf[bytesSent], recvBufSize-bytesSent, 0)) < 0)
      {
        syslog(LOG_INFO, "Couldn't send to talk connection in Step 1. Errno: %m");
        kill(ppid, SIGKILL);
        return 1;
      }
    }
    if(requestBuf)
    {
      char *tempBuf = (char*)malloc(requestSize+1);
      bufcpy(tempBuf, requestBuf, requestSize);
      free(requestBuf);
      requestBuf = (char*)malloc(requestSize+recvBufSize+1);
      bufcpy(requestBuf, tempBuf, requestSize);
      free(tempBuf);
    }
    else
      requestBuf = (char*)malloc(recvBufSize+1);
    
    bufcat(requestBuf, requestSize, listenBuf, recvBufSize);

    char endOfRequest = 0;
    int i;
    for(i = requestSize<4 ? 0 : requestSize-4; i<requestSize+recvBufSize-3; i++)
    {
      if(requestBuf[i]==CR && requestBuf[i+1]==LF && requestBuf[i+2]==CR && requestBuf[i+3]==LF)
      {
        endOfRequest = 1;
        break;
      }
    }
    requestSize+=recvBufSize;
    if(endOfRequest)  //TODO: this will not work for POST headers!
      break;
  }
  
  if(recvBufSize<0 && errno !=54) //an error, not the connection reset by peer that IE often produces, occured
  {
    if(logging)
      syslog(LOG_INFO, "NTLM authentication was interrupted by client. Killing session processes. Errno: %m.");
    kill(ppid, SIGKILL);
    return 1;
  }
  
  syslog(LOG_INFO, "Waiting for Step 2");
//  while(shmData->bStep2==0)
//    ; //loop until the other process sets this flag
      //now we'll assume that the server closed the connection after returning a 407.
  //infinite loops are full ghey, let try a stop signal instead. The stop will be cancelled with a continue from the other process.
  if(raise(SIGSTOP)<0)
  {
    syslog(LOG_ERR, "Failed to send stop signal in Step 2. Errno: %m.");
    return 1;
  }
  
  syslog(LOG_INFO, "Entering Step 3");
  /*****Step 3 - Client resubmits request to proxy, with a Type 1 authorization message*****/
      //first, insert the auth string into the headers
  char *authenticatedRequest = (char*)malloc(requestSize+30/*size of auth header*/+1);  //TODO: actually generate auth header
  int i;
  for(i=0; i<requestSize-1; i++)
    if(requestBuf[i] == CR && requestBuf[i+1] == LF)
      break;
  
  bufcpy(authenticatedRequest, requestBuf, i+2);
  bufcat(authenticatedRequest, i+2, "Authorization: NTLM ABCDEFGH", 28);
  bufcat(authenticatedRequest, i+30, CRLF, 2);
  bufcat(authenticatedRequest, i+32, &requestBuf[i+2], requestSize-i-2);
      //second, reestablish connection to server
  authenticatedRequest[requestSize+30]='\0';
  syslog(LOG_INFO, "To this: %s", authenticatedRequest);
  serverSocket = establishServerSide("127.0.0.1", 8088); //TODO: damn, we need to pass the address and port number through to this funtion... or can we be smarter about it and store it as a state variable or soemthing?
  if(serverSocket < 0)
  {
    syslog(LOG_ERR, "Couldn't open connection to proxy server. Errno: %m");
    return 1;
  }
  shmData->serverSocket = serverSocket;
//  shmData->bServerConnectionReestablished = 1;
  //using signals instead of polling for shared memory changes now
  if(kill(ppid, SIGCONT)<0)
  {
    syslog(LOG_ERR, "Failed to send continue signal in Step 3. Errno: %m");
    return 1;
  }
  
  int bytesSent=0;
      //thirdly, and lastly, send the request again to the proxy
  while(bytesSent<requestSize+30)
  {
    if((bytesSent += send(serverSocket, &authenticatedRequest[bytesSent], recvBufSize-bytesSent, 0)) < 0)
    {
      syslog(LOG_INFO, "Couldn't send to talk connection in Step 3. Errno: %m");
      kill(ppid, SIGKILL);
      return 1;
    }
  }
  
//  while(!(shmData->bStep4))
//    ; //loop until the other process sets this flag
      //now we'll assume that the server closed the connection after returning a second 407.
  //infinite loops are full ghey, let try a stop signal instead. The stop will be cancelled with a continue from the other process.
  if(raise(SIGSTOP)<0)
  {
    syslog(LOG_ERR, "Failed to send stop signal in Step 4. Errno: %m.");
    return 1;
  }
  
  syslog(LOG_INFO, "Entering Step 5");
  /*****Step 5 - Client resubmits request to proxy, with a Type 3 authorization message*****/
      //insert the auth string into the headers
  bufcpy(authenticatedRequest, requestBuf, i-1);
  bufcat(authenticatedRequest, i, "Authorization: NTLM ZYXWVUTSRQ", 30);
  bufcat(authenticatedRequest, i+30, &requestBuf[i], requestSize-i);
  bytesSent=0;
  while(bytesSent<requestSize+30)
  {
    if((bytesSent += send(serverSocket, &listenBuf[bytesSent], recvBufSize-bytesSent, 0)) < 0)
    {
      syslog(LOG_INFO, "Couldn't send to talk connection in Step 5. Errno: %m");
      kill(ppid, SIGKILL);
      return 1;
    }
  }
  
  free(requestBuf);
  free(authenticatedRequest);
  
  //now we can assume the authentication process is complete
  shmdt(shmData);
  shmctl(shmID, IPC_RMID, NULL);
  
  //okay, we are done authenticating! We can just let the data pass back and forward now.
  //this will be done in the existing "conduct" fuctions
  return 0;  
}