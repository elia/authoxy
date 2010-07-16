/*
*  NTLM.c
*  Authoxy
*
*  Created by Heath Raftery on Fri Jan 2 2004.
*  Copyright (c) 2004 HRSoftWorks. All rights reserved.
*

This file is part of Authoxy.

Authoxy is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Authoxy is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Authoxy; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include <libkern/OSByteOrder.h>

#include "AuthoxyDaemon.h"
#include "base64.h"

#include <openssl/md4.h>
#include <openssl/des.h>


//**************************************************************************
//	establishNTLMAuthentication(int clientConnection, int serverSocket, char logging, struct NTLMSettings *theNTLMSettings)
//
//	authenticate to the proxy using the NTLM scheme, so the client is free to continue
//  the method is unofficially documented in several places now, but the main reference
//  for this implementation was this:
//  http://davenport.sourceforge.net/ntlm.html#ntlmHttpAuthentication
//
//**************************************************************************
int establishNTLMAuthentication(int clientConnection, int *serverSocketPtr, int logging, struct NTLMSettings *theNTLMSettings)
{
  int serverSocket = *serverSocketPtr;

  struct sharedData *shmData;
  int shmID;
  //first, set up a shared memory space
  if(establishNTLMParentSetup(&shmData, &shmID))
  {
    close(clientConnection);
    close(serverSocket);
    return 1;
  }

  shmData->step1Started=0;
  shmData->step1Finished=0;
  shmData->step2Started=0;
  shmData->step2Finished=0;
  shmData->step3Started=0;
  shmData->step3Finished=0;
  shmData->step4Started=0;
  shmData->step4Finished=0;
  shmData->step5Started=0;
  shmData->step5Finished=0;

  if(logging)
    syslog(LOG_NOTICE, "Ready to NTLM!");

  int requestSize=0;
  char *authenticatedRequest=NULL;
  int authHeaderSize=0;
  int connectionClose=0;
  int connectionCloseHeaderSize=0;
  int authStringSize=0;
  char *authString=NULL;
  char *requestBuf=NULL;
  int indexForHeader=0;

  //okay, we're going to have to break into two processes to handle both ends of the connection, client->proxy and server->proxy
  pid_t pid;
  switch(pid = fork())			//spawn a new process to handle the request
  {
    case -1:						//trouble!!
      syslog(LOG_ERR, "Fatal Error. Unable to create new process: %m");
      close(clientConnection);
      exit(1);
      
    case 0:							//the child - server->client
      if(establishNTLMAuthenticationChildOne(clientConnection, serverSocket, logging))
      {
        pid_t ppid = getppid();
        close(clientConnection);
        close(serverSocket);
        kill(ppid, SIGCONT);
        kill(ppid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      else
      {
    //        close(clientConnection);
    //        close(serverSocket);
        exit(EXIT_SUCCESS);
      }

    default:                        //the parent - client->server
      if(establishNTLMAuthenticationParentOne(clientConnection, serverSocketPtr, logging, &requestSize, &authenticatedRequest, &authHeaderSize, &authStringSize, &authString, &requestBuf, &indexForHeader, &connectionClose, &connectionCloseHeaderSize, shmData, theNTLMSettings))
      {
        close(clientConnection);
        close(serverSocket);
        kill(pid, SIGCONT);
        kill(pid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      else
        break;
  }

  serverSocket = *serverSocketPtr;

  //connection is reestablished with server, so fork another process to handle the server->client stuff
  switch(pid = fork())			//spawn a new process to handle the request
  {
    case -1:						//trouble!!
      syslog(LOG_ERR, "Fatal Error. Unable to create new process: %m");
      close(clientConnection);
      exit(1);
      
    case 0:							//the child - new server->client
      if(establishNTLMAuthenticationChildTwo(clientConnection, serverSocket, logging))
      {
        pid_t ppid = getppid();
        close(clientConnection);
        close(serverSocket);
        kill(ppid, SIGCONT);
        kill(ppid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      else
        exit(EXIT_SUCCESS);
      
    default:                        //the parent - continue client->server
      if(establishNTLMAuthenticationParentTwo(clientConnection, serverSocket, logging, requestSize, authenticatedRequest, authHeaderSize, authStringSize, authString, requestBuf, indexForHeader, connectionClose, connectionCloseHeaderSize, shmData, theNTLMSettings))
      {
        close(clientConnection);
        close(serverSocket);
        kill(pid, SIGCONT);
        kill(pid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      else
        break;
  }

  //now we can assume the authentication process is complete
  shmdt(shmData);
  shmctl(shmID, IPC_RMID, NULL);

  return 0;
}

//**************************************************************************
//	establishNTLMAuthenticationParentOne(int clientConnection, int *serverSocketPtr, char logging, int *requestSizePtr, char **authenticatedRequestPtr, int *authHeaderSizePtr, int *authStringSizePtr, char **authStringPtr, char **requestBuf, int *indexForHeaderPtr, int *connectionClosePtr, int *connectionCloseHeaderSizePtr, struct sharedData *shmData, struct NTLMSettings *theNTLMSettings)
//
//	called by establishNTLMAuthentication() to handle the parent process
//
//**************************************************************************
int establishNTLMAuthenticationParentOne(int clientConnection, int *serverSocketPtr, int logging, int *requestSizePtr, char **authenticatedRequestPtr, int *authHeaderSizePtr, int *authStringSizePtr, char **authStringPtr, char **requestBufPtr, int *indexForHeaderPtr, int *connectionClosePtr, int *connectionCloseHeaderSizePtr, struct sharedData *shmData, struct NTLMSettings *theNTLMSettings)
{
  int serverSocket = *serverSocketPtr;

  int connectionClose=0, connectionCloseHeaderSize=strlen(CONNECTION_CLOSE_HEADER);
  int recvBufSize;
  int requestSize=*requestSizePtr;
  char listenBuf[INCOMING_BUF_SIZE], *requestBuf=*requestBufPtr;
  int endOfRequest=0, contentLength=0;
  if(logging)
    syslog(LOG_NOTICE, "Entering Step 1");
  
  shmData->step1Started=1;
  /*****Step 1 - Client sends regular, unauthenticated request to proxy*****/
  while((recvBufSize = recv(clientConnection, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)  //retrieve the data on the listen socket
  {
    if(requestBuf)
    {
      char *tempBuf = (char*)malloc(requestSize+recvBufSize);
      memcpy(tempBuf, requestBuf, requestSize);
      free(requestBuf);
      requestBuf = tempBuf;
    }
    else
      requestBuf = (char*)malloc(recvBufSize);

    memcpy(requestBuf + requestSize, listenBuf, recvBufSize);

    int i;
    for(i = (requestSize<connectionCloseHeaderSize) ? 0 : requestSize-connectionCloseHeaderSize; !connectionClose && i<requestSize+recvBufSize-connectionCloseHeaderSize-1; i++)
    {
      if(bufferMatchesStringAtIndex(requestBuf, CONNECTION_CLOSE_HEADER, i))
      {
        connectionClose = i;
        int n, m;
        for(n=i, m=i+19; m<requestSize+recvBufSize; n++, m++)
          requestBuf[n] = requestBuf[m];
        recvBufSize-=19;
        
        if(logging)
          syslog(LOG_NOTICE, "Found Connection: close. Hiding for NTLM Authentication");
      }
    }
    for(i = (requestSize<16) ? 0 : requestSize-16; !contentLength && i<requestSize+recvBufSize-15; i++)
    {
      if(bufferMatchesStringAtIndex(requestBuf, "Content-Length: ", i))
      {
        int n=0;
        contentLength = requestBuf[i+16]-'0';
        while(isdigit(requestBuf[i+17+n]))
        {
          contentLength*=10;
          contentLength+=(requestBuf[i+17+n++]-'0');
        }
        if(logging)
          syslog(LOG_NOTICE, "Content Length of request: %d", contentLength);
      }
    }
    for(i = (requestSize<4) ? 0 : requestSize-4; !endOfRequest && i<requestSize+recvBufSize-3; i++)
    {
      if(bufferMatchesStringAtIndex(requestBuf, CRLF, i) && bufferMatchesStringAtIndex(requestBuf, CRLF, i+2))
      {
        endOfRequest = i+4;
        break;
      }
    }
    requestSize+=recvBufSize;

    if(endOfRequest && requestSize >= endOfRequest + contentLength)
      break;
  }

  if(recvBufSize<0 && errno !=54) //an error, not the connection reset by peer that IE often produces, occured
  {
    if(logging)
      syslog(LOG_NOTICE, "NTLM authentication was interrupted by client. Killing session processes. Errno: %m.");
    return 1;
  }

  //otherwise, send the request to the server
  //this used to be inside the receive loop, but has moved to here to allow changes to be made to the request.
  int bytesSent=0;
  while(bytesSent<requestSize)
  {
    if((bytesSent += send(serverSocket, &requestBuf[bytesSent], requestSize-bytesSent, 0)) < 0)
    {
      syslog(LOG_NOTICE, "Couldn't send to talk connection in Step 1. Errno: %m");
      return 1;
    }
  }
  if(logging == TESTING)
    logClientToServer(requestBuf, bytesSent);

  int indexForHeader;
  for(indexForHeader=0; indexForHeader<requestSize-1; indexForHeader++)
    if(requestBuf[indexForHeader] == CR && requestBuf[indexForHeader+1] == LF)
      break;
  indexForHeader+=2;

  shmData->step1Finished=1;
  if(shmData->step2Finished)
  {
    if(logging)
      syslog(LOG_NOTICE, "Child too quick for us in Step 1. Continuing with Step 3.");
  }
  else
  {
    if(logging)
      syslog(LOG_NOTICE, "Waiting for Step 2");

  //Pause here
  if(raise(SIGSTOP)<0)
  {
    syslog(LOG_ERR, "Failed to send stop signal in Step 2. Errno: %m.");
    return 1;
  }
  }

  if(logging)
    syslog(LOG_NOTICE, "Entering Step 3");
  shmData->step3Started=1;
  /*****Step 3 - Client resubmits request to proxy, with a Type 1 authorization message*****/
  //first, insert the auth string into the headers
  int authStringSize=0;
  char *authString;
  if(establishNTLMGetType1StringBase64(&authString, &authStringSize, theNTLMSettings->domain, theNTLMSettings->host))
  {
    syslog(LOG_ERR, "Unable to generate Type 1 String.");
    return 1;
  }
  if(logging)
    syslog(LOG_NOTICE, "Created Type 1 string of %d characters", authStringSize);
  int authHeaderSize = strlen(AUTH_HEADER);
  char *authenticatedRequest = *authenticatedRequestPtr;
  authenticatedRequest = (char*)malloc(requestSize+authHeaderSize+authStringSize+2);
  memcpy(authenticatedRequest, requestBuf, indexForHeader);
  memcpy(authenticatedRequest + indexForHeader,                                 AUTH_HEADER, authHeaderSize);
  memcpy(authenticatedRequest + indexForHeader+authHeaderSize,                  authString, authStringSize);
  memcpy(authenticatedRequest + indexForHeader+authHeaderSize+authStringSize,   CRLF, 2);
  memcpy(authenticatedRequest + indexForHeader+authHeaderSize+authStringSize+2, &requestBuf[indexForHeader], requestSize-indexForHeader);

  if(authStringSize)
    free(authString);

  //second, reestablish connection to server
  serverSocket = establishServerSide(NULL, 0); //connect again to the last server connected to
  *serverSocketPtr = serverSocket;

  if(serverSocket < 0)
  {
    syslog(LOG_ERR, "Couldn't open connection to proxy server. Errno: %m");
    return 1;
  }

  *requestSizePtr = requestSize;
  *authenticatedRequestPtr = authenticatedRequest;
  *authHeaderSizePtr = authHeaderSize;
  *authStringSizePtr = authStringSize;
  *authStringPtr = authString;
  *requestBufPtr = requestBuf;
  *indexForHeaderPtr = indexForHeader;
  *connectionClosePtr = connectionClose;
  *connectionCloseHeaderSizePtr = connectionCloseHeaderSize;

  return 0;
}

//**************************************************************************
//	establishNTLMAuthenticationParentTwo(int clientConnection, int serverSocket, char logging, int requestSize, char *authenticatedRequest, int authHeaderSize, int authStringSize, char *authString, char *requestBuf, int indexForHeader, int connectionClose, int connectionCloseHeaderSize, struct sharedData *shmData, struct NTLMSettings *theNTLMSettings)
//
//	called by establishNTLMAuthentication() to handle the parent process
//
//**************************************************************************
int establishNTLMAuthenticationParentTwo(int clientConnection, int serverSocket, int logging, int requestSize, char *authenticatedRequest, int authHeaderSize, int authStringSize, char *authString, char *requestBuf, int indexForHeader, int connectionClose, int connectionCloseHeaderSize, struct sharedData *shmData, struct NTLMSettings *theNTLMSettings)
{
  int bytesSent=0;
  //thirdly, and lastly, send the request again to the proxy
  while(bytesSent<requestSize+authHeaderSize+authStringSize+2)
  {
    if((bytesSent += send(serverSocket, &authenticatedRequest[bytesSent], requestSize+authHeaderSize+authStringSize+2-bytesSent, 0)) < 0)
    {
      syslog(LOG_NOTICE, "Couldn't send to talk connection in Step 3. Errno: %m");
      return 1;
    }
  }
  if(logging == TESTING)
    logClientToServer(authenticatedRequest, bytesSent);
  
  shmData->step3Finished=1;
  if(shmData->step4Finished)
  {
    if(logging)
      syslog(LOG_NOTICE, "Child too quick for us in Step 3. Continuing with Step 5");
  }
  else
  {
    if(logging)
      syslog(LOG_NOTICE, "Pausing in Step 3");
    //Pause here for a moment. The stop will be cancelled with a continue from the other process.
    if(raise(SIGSTOP)<0)
    {
      syslog(LOG_ERR, "Failed to send stop signal in Step 4. Errno: %m.");
      return 1;
    }
  }

  free(authenticatedRequest);
  authStringSize=0;

  if(logging)
  syslog(LOG_NOTICE, "Entering Step 5");
  shmData->step5Started=1;
  /*****Step 5 - Client resubmits request to proxy, with a Type 3 authorization message*****/
  unsigned char nonce[8];
  memcpy((char*)nonce, shmData->nonce, 8);

  if(establishNTLMGetType3StringBase64(&authString, &authStringSize, theNTLMSettings->username, theNTLMSettings->password, theNTLMSettings->host, theNTLMSettings->domain, nonce))
    return 1;

  if(logging)
    syslog(LOG_NOTICE, "Got Type 3 msg of %d characters.", authStringSize);
  //insert the auth string into the headers
  authenticatedRequest = (char*)malloc(requestSize+authHeaderSize+authStringSize+2);
  memcpy(authenticatedRequest, requestBuf, indexForHeader);
  memcpy(authenticatedRequest + indexForHeader,                                 AUTH_HEADER, authHeaderSize);
  memcpy(authenticatedRequest + indexForHeader+authHeaderSize,                  authString, authStringSize);
  memcpy(authenticatedRequest + indexForHeader+authHeaderSize+authStringSize,   CRLF, 2);
  memcpy(authenticatedRequest + indexForHeader+authHeaderSize+authStringSize+2, &requestBuf[indexForHeader], requestSize-indexForHeader);
  requestSize = requestSize+authHeaderSize+authStringSize+2;

  //if necessary, put the Connection: close header back in
  if(connectionClose)
  {
    //note that we can't put it back in the same spot, because the header will have changed with the authentication stuff in.
    char *connectionCloseRequest = (char*)malloc(requestSize+connectionCloseHeaderSize+2);
    memcpy(connectionCloseRequest, authenticatedRequest, indexForHeader);
    memcpy(connectionCloseRequest + indexForHeader,                              CONNECTION_CLOSE_HEADER, connectionCloseHeaderSize);
    memcpy(connectionCloseRequest + indexForHeader+connectionCloseHeaderSize,    CRLF, 2);
    memcpy(connectionCloseRequest + indexForHeader+connectionCloseHeaderSize+2,  &authenticatedRequest[indexForHeader], requestSize-indexForHeader);
    free(authenticatedRequest);
    authenticatedRequest = connectionCloseRequest;
    requestSize = requestSize + connectionCloseHeaderSize+2;
  }

  bytesSent=0;
  while(bytesSent<requestSize)
  {
    if((bytesSent += send(serverSocket, &authenticatedRequest[bytesSent], requestSize-bytesSent, 0)) < 0)
    {
      syslog(LOG_NOTICE, "Couldn't send to talk connection in Step 5. Errno: %m");
      return 1;
    }
  }
  if(logging == TESTING)
    logClientToServer(authenticatedRequest, bytesSent);

  if(authStringSize)
    free(authString);
  free(authenticatedRequest);
  free(requestBuf);

  shmData->step5Finished=1;

  return 0;
}

//**************************************************************************
//	establishNTLMAuthenticationChildOne(int clientConnection, int serverSocket, char logging)
//
//	called by establishNTLMAuthentication() to handle the child process
//
//**************************************************************************
int establishNTLMAuthenticationChildOne(int clientConnection, int serverSocket, int logging)
{
  struct sharedData *shmData;
  pid_t ppid;
  if(establishNTLMChildSetup(&shmData, clientConnection, &ppid))
    return 1;
  
  int recvBufSize, responseSize=0;
  int contentLength=0, endOfResponse=0;
  char listenBuf[INCOMING_BUF_SIZE+1], *responseBuf=NULL;
  /*****Step 2 - Proxy returns a 407 Unauthorised to the client*****/
  if(logging)
    syslog(LOG_NOTICE, "Entering Step 2");
  shmData->step2Started=1;
  while((recvBufSize = recv(serverSocket, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)
  {
    if(responseBuf)
    {
      char *tempBuf = (char*)malloc(responseSize+recvBufSize);
      memcpy(tempBuf, responseBuf, responseSize);
      free(responseBuf);
      responseBuf = tempBuf;
    }
    else
      responseBuf = (char*)malloc(recvBufSize);

    memcpy(responseBuf + responseSize, listenBuf, recvBufSize);

    int i;
    for(i = (responseSize<16) ? 0 : responseSize-16; !contentLength && i<responseSize+recvBufSize-15; i++)
    {
      if(bufferMatchesStringAtIndex(responseBuf, "Content-Length: ", i))
      {
        int n=0;
        contentLength = responseBuf[i+16]-'0';
        while(isdigit(responseBuf[i+17+n]))
        {
          contentLength*=10;
          contentLength+=(responseBuf[i+17+n++]-'0');
        }
        if(logging)
          syslog(LOG_NOTICE, "Content Length of response: %d", contentLength);
      }
    }
    for(i = (responseSize<4) ? 0 : responseSize-4; !endOfResponse && i<responseSize+recvBufSize-3; i++)
    {
      if(bufferMatchesStringAtIndex(responseBuf, CRLF, i) && bufferMatchesStringAtIndex(responseBuf, CRLF, i+2))
      {
        endOfResponse = i+4;
        break;
      }
    }
    responseSize+=recvBufSize;

    if(endOfResponse && responseSize >= endOfResponse + contentLength)
      break;
  }
  if(recvBufSize<0)
  {
    if(logging)
      syslog(LOG_NOTICE, "Server closed ungracefully in NTLM authentication Step 2. Killing session processes. Errno: %m.");
    return 1;
  }
  if(logging == TESTING)
    logServerToClient(responseBuf, responseSize);

  close(serverSocket);

  if(strncmp(&responseBuf[9]/*HTTP/1.x */, "407", 3) != 0) //did the proxy return a proxy authentication required error?
  {
    syslog(LOG_ERR, "Unexpected server response in NTLM authentication Step 2. Giving up.");
    free(responseBuf);
    return 1;
  }

  //otherwise, step 2 is complete
  if(logging)
    syslog(LOG_NOTICE, "Step 2 is complete");
  shmData->step2Finished=1;

  if(!(shmData->step3Started))
  {
    if(kill(ppid, SIGCONT)<0)
    {
      syslog(LOG_ERR, "Failed to send continue signal in Step 2: %m");
      free(responseBuf);
      return 1;
    }
  }

  //our connection should have been broken by the server, so this parent is going to die now, and let the new child of the child pick up the act.
  free(responseBuf);
  return 0;
}

//**************************************************************************
//	establishNTLMAuthenticationChildTwo(int clientConnection, int serverSocket, char logging)
//
//	Called by establishNTLMAuthentication() to handle the child process
//  The function actually continues the work of the original child, but with a
//  copy of the new file descriptors established in the parent
//**************************************************************************
int establishNTLMAuthenticationChildTwo(int clientConnection, int serverSocket, int logging)
{
  struct sharedData *shmData;
  pid_t ppid;
  if(establishNTLMChildSetup(&shmData, clientConnection, &ppid))
    return 1;

  int recvBufSize, responseSize=0;
  char listenBuf[INCOMING_BUF_SIZE+1], *responseBuf=NULL;
  int contentLength=0;
  int endOfResponse = 0;

  if(logging)
    syslog(LOG_NOTICE, "Entering Step 4");
  
  shmData->step4Started=1;
  /*****Step 4 - Proxy returns another 407 Unauthorised to the client*****/
  while((recvBufSize = recv(serverSocket, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)
  {
    if(responseBuf)
    {
      char *tempBuf = (char*)malloc(responseSize+recvBufSize);
      memcpy(tempBuf, responseBuf, responseSize);
      free(responseBuf);
      responseBuf = tempBuf;
    }
    else
      responseBuf = (char*)malloc(recvBufSize);

    memcpy(responseBuf + responseSize, listenBuf, recvBufSize);

    int i;
    for(i = responseSize<16 ? 0 : responseSize-16; i<responseSize+recvBufSize-15; i++)
    {
      if(!contentLength && bufferMatchesStringAtIndex(responseBuf, "Content-Length: ", i))
      {
        int n=0;
        contentLength = responseBuf[i+16]-'0';
        while(isdigit(responseBuf[i+17+n]))
        {
          contentLength*=10;
          contentLength+=(responseBuf[i+17+n++]-'0');
        }
        if(logging)
          syslog(LOG_NOTICE, "Content-Length: %d", contentLength);
      }
    }
    for(i = responseSize<4 ? 0 : responseSize-4; i<responseSize+recvBufSize-3; i++)
    {
      if(bufferMatchesStringAtIndex(responseBuf, CRLF, i) && bufferMatchesStringAtIndex(responseBuf, CRLF, i+2))
      {
        endOfResponse = i+4;
        break;
      }
    }
    responseSize+=recvBufSize;

    if(endOfResponse && responseSize >= endOfResponse + contentLength)
      break;
  }
  if(recvBufSize<0)
  {
    syslog(LOG_NOTICE, "Server closed ungracefully in NTLM authentication Step 4. Killing session processes: %m.");
    return 1;
  }
  if(logging == TESTING)
    logServerToClient(responseBuf, responseSize);
  
  if(strncmp(&responseBuf[9]/*HTTP/1.x */, "407", 3) != 0) //did the proxy return a proxy authentication required error?
  {
    syslog(LOG_ERR, "Unexpected server response in NTLM authentication Step 4. Giving up.");
    free(responseBuf);
    return 1;
  }

  //find the Type 2 challenge
  int i;
  const int HEADER_LENGTH = 25;
  for(i=0; i<responseSize-HEADER_LENGTH; i++)
    if(bufferMatchesStringAtIndex(responseBuf, "Proxy-Authenticate: NTLM ", i))
      break;
  if(i==responseSize-HEADER_LENGTH)
  {
    syslog(LOG_ERR, "No authentication challenge in NTLM authentication Step 4. Giving up.");
    free(responseBuf);
    return 1;
  }

  int authStringSize=0, startOfAuthString = i+HEADER_LENGTH;
  for(i=startOfAuthString; i<responseSize-1 && !bufferMatchesStringAtIndex(responseBuf, CRLF, i); i++)
    authStringSize++;
  char authString[authStringSize];
  for(i=0; i<authStringSize; i++)
    authString[i] = responseBuf[startOfAuthString+i];
  char *nonce;
  if(establishNTLMParseType2StringBase64(authString, authStringSize, &nonce, logging))
  {
    free(responseBuf);
    return 1;
  }
  //otherwise, step 4 is complete
  if(logging)
    syslog(LOG_NOTICE, "The nonce is: %8s.", nonce);
  memcpy(shmData->nonce, nonce, 8);
  free(nonce);

  shmData->step4Finished=1;
  if(logging)
    syslog(LOG_NOTICE, "Finished Step 4");
  if(!(shmData->step5Started))
  {
    if(kill(ppid, SIGCONT)<0)
    {
      syslog(LOG_ERR, "Failed to send continue signal in Step 4: %m");
      free(responseBuf);
      return 1;
    }
  }

  //hopefully at this stage, the client will send the final authentication header, and the server will respond with the originally requested data
  //this stage of the communication will be handled by the regular conduct* functions.
  free(responseBuf);

  return 0;
}

//**************************************************************************
//	establishNTLMParentSetup(struct sharedData **shmData, int *shmID)
//
//	Set up a few things for the NTLM parent processes, so they can do their work
//**************************************************************************
int establishNTLMParentSetup(struct sharedData **shmData, int *shmID)
{
  key_t shmKey;
  //  FILE *f = fopen("/tmp/authoxydThreadStuff", "w"); //should be created in main()
  //  fclose(f);
  if((shmKey = ftok(AUTHOXYD_PID_PATH, getpid())) == -1) //note that ftok will only look at the lower 8 bits of the PID. Hopefully this part of the PID
  {                                                               //will actually change enough to give us a unique key
    syslog(LOG_ERR, "Fatal Error. Unable to get a key for shared memory: %m");
    return 1;
  }
  if((*shmID = shmget(shmKey, sizeof(struct sharedData), 0644 | IPC_CREAT)) == -1)
  {
    syslog(LOG_ERR, "Fatal Error. Unable to create shared memory: %m");
    return 1;
  }
  if((*shmData = shmat(*shmID, (void *)0, 0)) == (struct sharedData*)(-1))
  {
    syslog(LOG_ERR, "Fatal Error. Unable to connect to shared memory: %m");
    return 1;    
  }
  return 0;
}

//**************************************************************************
//	establishNTLMChildSetup(struct sharedData **shmData, int clientConnection, pid_t &ppid)
//
//	Set up a few things for the NTLM child processes, so they can do their work
//**************************************************************************
int establishNTLMChildSetup(struct sharedData **shmData, int clientConnection, pid_t *ppid)
{
  //connect to the shared memory data structure
  key_t shmKey;
  int shmID;
  if((shmKey = ftok(AUTHOXYD_PID_PATH, getppid())) == -1)  //see equivalent call in ParentSetup for discussion
  {
    syslog(LOG_ERR, "Fatal Error. Unable to get a key for shared memory: %m");
    return 1;
  }
  if((shmID = shmget(shmKey, sizeof(struct sharedData), 0)) == -1)
  {
    syslog(LOG_ERR, "Fatal Error. Unable to connect to shared memory: %m");
    return 1;    
  }
  if((*shmData = shmat(shmID, (void *)0, 0)) == (struct sharedData*)(-1))
  {
    syslog(LOG_ERR, "Fatal Error. Unable to connect to shared memory: %m");
    return 1;    
  }

  //  close(clientConnection);  //not needed by the child

  *ppid = getppid();

return 0;
}

//**************************************************************************
//	establishNTLMGetType1String(char **authString, int *authStringSize, const char *domain, const char *workstation)
//
//	allocate memory to, and return the Type 1 NTLM authorization string in authString and its size in authStringSize
//**************************************************************************
int establishNTLMGetType1String(char **authString, int *authStringSize, const char *domain, const char *workstation)
{
  int i, domLen = strlen(domain), workLen = strlen(workstation);
  struct type1Message msg;
  long datal;
  short datas;
  strcpy(msg.protocol, "NTLMSSP");
  datal = 1;
  msg.type = OSSwapHostToLittleInt32(datal);
  datal = NTLM_FLAG_NEGOTIATE_OEM | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NEGOTIATE_NTLM | NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED | NTLM_FLAG_NEGOTIATE_WORKSTATION_SUPPLIED;
  msg.flags = OSSwapHostToLittleInt32(datal);
  datas = domLen;
  msg.domain.length = OSSwapHostToLittleInt16(datas);
  msg.domain.length2 = OSSwapHostToLittleInt16(datas);
  datal = workLen + sizeof(msg);
  msg.domain.offset = OSSwapHostToLittleInt32(datal);
  datas = workLen;
  msg.host.length = OSSwapHostToLittleInt16(datas);
  msg.host.length2 = OSSwapHostToLittleInt16(datas);
  datal = sizeof(msg);
  msg.host.offset = OSSwapHostToLittleInt32(datal);

  *authStringSize = sizeof(msg)+domLen+workLen;
  *authString = (char*)malloc(*authStringSize);
  char *msgPtr = (char*)&msg;
  for(i=0; i<sizeof(msg); i++)
    (*authString)[i] = msgPtr[i];
  int j;
  for(j=0; j<workLen; j++, i++)
    (*authString)[i] = toupper(workstation[j]);
  for(j=0; j<domLen; j++, i++)
    (*authString)[i] = toupper(domain[j]);

  return 0;
}

//**************************************************************************
//	establishNTLMGetType1StringBase64(char **authString, int *authStringSize, const char *domain, const char *workstation)
//
//	return the base64 version of the Type 1 message
//**************************************************************************
int establishNTLMGetType1StringBase64(char **authString, int *authStringSize, const char *domain, const char *workstation)
{
  if(establishNTLMGetType1String(authString, authStringSize, domain, workstation))
  return 1;

  char *encoded = encodeString(*authString, authStringSize);
  free(*authString);
  *authString = encoded;
  return 0;
}  

//**************************************************************************
//	establishNTLMParseType2String(char **authString, char **nonce, char logging)
//
//**************************************************************************
int establishNTLMParseType2String(char *authString, int authStringSize, char **nonce, int logging)
{
  struct type2Message *msgPtr = (struct type2Message*)authString;
  long datal;
  short datas;

  if(strcmp(msgPtr->protocol, "NTLMSSP") != 0)
  {
    syslog(LOG_ERR, "Error in parsing NTLM Type 2 message: unexpected protocol.");
    return 1;
  }
  datal = 2;
  if(msgPtr->type != OSSwapHostToLittleInt32(datal))
  {
    syslog(LOG_ERR, "Error in parsing NTLM Type 2 message: unexpected type.");
    return 1;    
  }

  datas = OSSwapLittleToHostInt16(msgPtr->target.length);
  if(logging) syslog(LOG_NOTICE, "NTLM: Target length is %d", datas);
    datas = OSSwapLittleToHostInt16(msgPtr->target.length2);
  if(logging) syslog(LOG_NOTICE, "NTLM: Target length 2 is %d", datas);
    datal = OSSwapLittleToHostInt32(msgPtr->target.offset);
  if(logging) syslog(LOG_NOTICE, "NTLM: Target offset is %d", datal);

  datal = OSSwapLittleToHostInt32(msgPtr->flags);
  if(logging)
  {
    if(datal & NTLM_FLAG_NEGOTIATE_UNICODE)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Unicode");
    if(datal & NTLM_FLAG_NEGOTIATE_OEM)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate OEM");
    if(datal & NTLM_FLAG_REQUEST_TARGET)
      syslog(LOG_NOTICE, "NTLM Flag: Request Target");
    if(datal & NTLM_FLAG_UNKNOWN1)
      syslog(LOG_NOTICE, "NTLM Flag: Unknown1");
    if(datal & NTLM_FLAG_NEGOTIATE_SIGN)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Sign");
    if(datal & NTLM_FLAG_NEGOTIATE_SEAL)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Seal");
    if(datal & NTLM_FLAG_NEGOTIATE_DATAGRAM_STYLE)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Datagram Style");
    if(datal & NTLM_FLAG_NEGOTIATE_LAN_MANAGER_KEY)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate LAN Manager Key");
    if(datal & NTLM_FLAG_NEGOTIATE_NETWARE)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Netware");
    if(datal & NTLM_FLAG_NEGOTIATE_NTLM)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate NTLM");
    if(datal & NTLM_FLAG_UNKNOWN2)
      syslog(LOG_NOTICE, "NTLM Flag: Unknown2");
    if(datal & NTLM_FLAG_UNKNOWN3)
      syslog(LOG_NOTICE, "NTLM Flag: Unknown3");
    if(datal & NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Domain Supplied");
    if(datal & NTLM_FLAG_NEGOTIATE_WORKSTATION_SUPPLIED)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Workstation Supplied");
    if(datal & NTLM_FLAG_NEGOTIATE_LOCAL_CALL)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Local Call");
    if(datal & NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Always Sign");
    if(datal & NTLM_FLAG_TARGET_TYPE_DOMAIN)
      syslog(LOG_NOTICE, "NTLM Flag: Target Type Domain");
    if(datal & NTLM_FLAG_TARGET_TYPE_SERVER)
      syslog(LOG_NOTICE, "NTLM Flag: Target Type Server");
    if(datal & NTLM_FLAG_TARGET_TYPE_SHARE)
      syslog(LOG_NOTICE, "NTLM Flag: Target Type Share");
    if(datal & NTLM_FLAG_NEGOTIATE_NTLM2_KEY)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate NTLM2 Key");
    if(datal & NTLM_FLAG_REQUEST_INIT_RESPONSE)
      syslog(LOG_NOTICE, "NTLM Flag: Request Init Response");
    if(datal & NTLM_FLAG_REQUEST_ACCEPT_RESPONSE)
      syslog(LOG_NOTICE, "NTLM Flag: Request Accept Response");
    if(datal & NTLM_FLAG_REQUEST_NON_NT_SESSION_KEY)
      syslog(LOG_NOTICE, "NTLM Flag: Request Non-NT Session Key");
    if(datal & NTLM_FLAG_NEGOTIATE_TARGET_INFO)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Target Info");
    if(datal & NTLM_FLAG_UNKNOWN4)
      syslog(LOG_NOTICE, "NTLM Flag: UNKNOWN4");
    if(datal & NTLM_FLAG_UNKNOWN5)
      syslog(LOG_NOTICE, "NTLM Flag: UNKNOWN5");
    if(datal & NTLM_FLAG_UNKNOWN6)
      syslog(LOG_NOTICE, "NTLM Flag: UNKNOWN6");
    if(datal & NTLM_FLAG_UNKNOWN7)
      syslog(LOG_NOTICE, "NTLM Flag: UNKNOWN7");
    if(datal & NTLM_FLAG_UNKNOWN8)
      syslog(LOG_NOTICE, "NTLM Flag: UNKNOWN8");
    if(datal & NTLM_FLAG_NEGOTIATE_128)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate 128");
    if(datal & NTLM_FLAG_NEGOTIATE_KEY_EXCHANGE)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate Key Exchange");
    if(datal & NTLM_FLAG_NEGOTIATE_56)
      syslog(LOG_NOTICE, "NTLM Flag: Negotiate 56");
  }
  *nonce = (char*)malloc(8);
  int i;
  for(i=0; i<8; i++)
    (*nonce)[i] = msgPtr->nonce[i];

  if(OSSwapLittleToHostInt16(msgPtr->target.length))  //well, there appears to be something there. Better print it out I guess
  {
    int len = OSSwapLittleToHostInt16(msgPtr->target.length);
    int off = OSSwapLittleToHostInt32(msgPtr->target.offset);
    char target[len+1];
    memcpy(target, &authString[off], len);
    for(i=0; i<len; i++)
      if(target[i]=='\0')
        target[i]='^';
    target[len]='\0';
    if(logging)
      syslog(LOG_NOTICE, "NTLM: Target is: %s", target);
  }

  datal = OSSwapLittleToHostInt32(msgPtr->flags);
  if(datal & NTLM_FLAG_NEGOTIATE_TARGET_INFO) //have a look at the target information buffer
  {
    datas = OSSwapLittleToHostInt16(msgPtr->targetInfo.length);
    if(logging) syslog(LOG_NOTICE, "NTLM: Target length is %d", datas);
    datas = OSSwapLittleToHostInt16(msgPtr->targetInfo.length2);
    if(logging) syslog(LOG_NOTICE, "NTLM: Target length 2 is %d", datas);
    datal = OSSwapLittleToHostInt32(msgPtr->targetInfo.offset);
    if(logging) syslog(LOG_NOTICE, "NTLM: Target offset is %d", datal);

    if(OSSwapLittleToHostInt16(msgPtr->targetInfo.length))  //well, there appears to be something there. Better print it out I guess
    {
      int len = OSSwapLittleToHostInt16(msgPtr->targetInfo.length);
      int off = OSSwapLittleToHostInt32(msgPtr->targetInfo.offset);
      char targetInfo[len+1];
      memcpy(targetInfo, &authString[off], len);
      for(i=0; i<len; i++)
        if(targetInfo[i]=='\0')
          targetInfo[i]='^';
      targetInfo[len]='\0';
      if(logging)
        syslog(LOG_NOTICE, "NTLM: TargetInfo is: %s", targetInfo);
    }
  }

  return 0;
}

//**************************************************************************
//	establishNTLMParseType2StringBase64(char **authString, char **nonce, char logging)
//
//**************************************************************************
int establishNTLMParseType2StringBase64(char *authString, int authStringSize, char **nonce, int logging)
{
  int returnValue=0;

  char *decoded = decodeString(authString, &authStringSize);

  if(establishNTLMParseType2String(decoded, authStringSize, nonce, logging))
    returnValue=1;

  free(decoded);
  return returnValue;
}

//**************************************************************************
//	establishNTLMGetType3String(char **authString, int *authStringSize, const char *username, const char *password, const char *host, const char *domain, const char *nonce)
//
//	allocate memory to, and return the Type 3 NTLM authorization string in authString and its size in authStringSize
//
//**************************************************************************
int establishNTLMGetType3String(char **authString, int *authStringSize, const char *username, const char *password, const char *host, const char *domain, const unsigned char *nonce)
{
  int i, userLen = strlen(username), hostLen = strlen(domain), domLen = strlen(domain); 
  struct type3Message msg;
  long datal;
  short datas;
  strcpy(msg.protocol, "NTLMSSP");
  datal = 3;
  msg.type = OSSwapHostToLittleInt32(datal);

  datas = 24;
  msg.LMResponse.length = OSSwapHostToLittleInt16(datas);
  msg.LMResponse.length2= OSSwapHostToLittleInt16(datas);
  datal = sizeof(msg) + domLen + userLen + hostLen;
  msg.LMResponse.offset = OSSwapHostToLittleInt32(datal);

  datas = 24;
  //  datas = 0;
  msg.NTResponse.length = OSSwapHostToLittleInt16(datas);
  msg.NTResponse.length2= OSSwapHostToLittleInt16(datas);
  datal = sizeof(msg) + domLen + userLen + hostLen + OSSwapLittleToHostInt16(msg.LMResponse.length2);
  msg.NTResponse.offset = OSSwapHostToLittleInt32(datal);

  datas = domLen;
  msg.domain.length = OSSwapHostToLittleInt16(datas);
  msg.domain.length2= OSSwapHostToLittleInt16(datas);
  datal = 64;
  msg.domain.offset = OSSwapHostToLittleInt32(datal);

  datas = userLen;
  msg.username.length = OSSwapHostToLittleInt16(datas);
  msg.username.length2= OSSwapHostToLittleInt16(datas);
  datal = 64 + domLen;
  msg.username.offset = OSSwapHostToLittleInt32(datal);

  datas = hostLen;
  msg.host.length = OSSwapHostToLittleInt16(datas);
  msg.host.length2= OSSwapHostToLittleInt16(datas);
  datal = 64 + domLen + userLen;
  msg.host.offset = OSSwapHostToLittleInt32(datal);

  datas = 0;
  msg.sessionKey.length = OSSwapHostToLittleInt16(datas);
  msg.sessionKey.length2= OSSwapHostToLittleInt16(datas);
  datal = sizeof(msg) + domLen + userLen + hostLen + OSSwapLittleToHostInt16(msg.LMResponse.length2) + OSSwapLittleToHostInt16(msg.NTResponse.length2);
  msg.sessionKey.offset = OSSwapHostToLittleInt32(datal);

  //same flags as step 1
  datal = NTLM_FLAG_NEGOTIATE_OEM | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NEGOTIATE_NTLM | NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED | NTLM_FLAG_NEGOTIATE_WORKSTATION_SUPPLIED;
  msg.flags = OSSwapHostToLittleInt32(datal);

  *authStringSize = sizeof(msg) + domLen + userLen + hostLen + OSSwapLittleToHostInt16(msg.LMResponse.length2) + OSSwapLittleToHostInt16(msg.NTResponse.length2);
  *authString = (char*)malloc(*authStringSize);
  char *msgPtr = (char*)&msg;
  for(i=0; i<sizeof(msg); i++)
    (*authString)[i] = msgPtr[i];
  int j;
  for(j=0; j<domLen; j++, i++)
    (*authString)[i] = toupper(domain[j]);
  for(j=0; j<userLen; j++, i++)
    (*authString)[i] = toupper(username[j]);
  for(j=0; j<hostLen; j++, i++)
    (*authString)[i] = toupper(host[j]);

  char *NTLMResponse=NULL;
  establishNTLMGetHashedPassword(&NTLMResponse, password, nonce);
  for(j=0; j<OSSwapLittleToHostInt16(msg.LMResponse.length2) + OSSwapLittleToHostInt16(msg.NTResponse.length2); j++, i++)
    (*authString)[i] = NTLMResponse[j];

  if(NTLMResponse)
    free(NTLMResponse);

  return 0;
}

//**************************************************************************
//	establishNTLMGetType3StringBase64(char **authString, int *authStringSize, const char *user, const char *password, const char *host, const char *domain, const char *nonce)
//
//	return the base64 version of the Type 3 message
//
//**************************************************************************
int establishNTLMGetType3StringBase64(char **authString, int *authStringSize, const char *username, const char *password, const char *host, const char *domain, const unsigned char *nonce)
{
  if(establishNTLMGetType3String(authString, authStringSize, username, password, host, domain, nonce))
    return 1;

  char *encoded = encodeString(*authString, authStringSize);
  free(*authString);
  *authString = encoded;

  return 0;
}

//**************************************************************************
//	establishNTLMGetHashedPassword(const char *password, const char *nonce)
//
//	returns the LM and NT hashed password in response
//
//**************************************************************************
//ex-nested function
/*
* turns a 56 bit key into the 64 bit, odd parity key and sets the key.
* The key schedule ks is also set.
*/
void SetupDESKey(unsigned char key56[], DES_key_schedule ks)
{
  DES_cblock key;

  key[0] = key56[0];
  key[1] = ((key56[0] << 7) & 0xFF) | (key56[1] >> 1);
  key[2] = ((key56[1] << 6) & 0xFF) | (key56[2] >> 2);
  key[3] = ((key56[2] << 5) & 0xFF) | (key56[3] >> 3);
  key[4] = ((key56[3] << 4) & 0xFF) | (key56[4] >> 4);
  key[5] = ((key56[4] << 3) & 0xFF) | (key56[5] >> 5);
  key[6] = ((key56[5] << 2) & 0xFF) | (key56[6] >> 6);
  key[7] =  (key56[6] << 1) & 0xFF;

  DES_set_odd_parity(&key);
  DES_set_key(&key, &ks);
};

//ex-nested function 2
/*
* takes a 21 byte array and treats it as 3 56-bit DES keys. The
* 8 byte plaintext is encrypted with each key and the resulting 24
* bytes are stored in the results array.
*/
void CalculateResponse(unsigned char *keys, const unsigned char *plaintext, unsigned char *results)
{
  DES_key_schedule ks;
  
  SetupDESKey(keys, ks);
  DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)results, &ks, DES_ENCRYPT);
  
  SetupDESKey(&keys[7], ks);
  DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)(&results[8]), &ks, DES_ENCRYPT);
  
  SetupDESKey(&keys[14], ks);
  DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)(&results[16]), &ks, DES_ENCRYPT);
};

//actual function
int establishNTLMGetHashedPassword(char **response, const char *password, const unsigned char *nonce)
{
  //firstly, the Lan Manager password
  unsigned char LMPassword[14];
  int passLen = strlen(password);
  
  int i;
  for(i=0; i<(passLen>14?14:passLen); i++)
    LMPassword[i] = toupper(password[i]);
  for(; i<14; i++)
    LMPassword[i] = '\0';
  
  unsigned char magic[] = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 }; //"KGS!@#$%"
  unsigned char LMHashedPassword[21];
  DES_key_schedule ks;
  
  SetupDESKey(LMPassword, ks);
  DES_ecb_encrypt((const_DES_cblock*)magic, (DES_cblock*)LMHashedPassword, &ks, DES_ENCRYPT);  //NOTE: kinda dodge - maybe I should learn this DES shit and do it properly
                                                                                              //atm, the DES_ENCRYPT is a guess, there is typecasting, the man page recommends not using
                                                                                              //these functions directly, and I'm forced to use old OpenSSL stuff
  SetupDESKey(&LMPassword[7], ks);
  DES_ecb_encrypt((const_DES_cblock*)magic, (DES_cblock*)&LMHashedPassword[8], &ks, DES_ENCRYPT);
  
  memset(&LMHashedPassword[16], 0, 5);
  
  //Secondly, the NT password
  char NTPassword[2*passLen];
  for(i=0; i<passLen; i++)
  {
    NTPassword[2*i]   = password[i];
    NTPassword[2*i+1] = 0;
  }
  
  unsigned char NTHashedPassword[21];
  MD4_CTX context;
  MD4_Init(&context);
  MD4_Update(&context, NTPassword, 2*passLen);
  MD4_Final(NTHashedPassword, &context);
  
  memset(&NTHashedPassword[16], 0, 5);
  
  //finally, create the responses
  unsigned char LMResponse[24], NTResponse[24];
  CalculateResponse(LMHashedPassword, nonce, LMResponse);
  CalculateResponse(NTHashedPassword, nonce, NTResponse);
  
  *response = (char*)malloc(24 + 24);
  for(i=0; i<24; i++)
    (*response)[i] = LMResponse[i];
  for(i=0; i<24; i++)
    (*response)[i+24] = NTResponse[i];
  
  return 0;
}
