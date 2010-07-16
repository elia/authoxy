/*
 *  connections.c
 *  Authoxy
 *
 *  Created by Heath Raftery on Mon Nov 11 2002.
 *  Copyright (c) 2002, 2003, 2004 HRSoftWorks. All rights reserved.
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

#include "AuthoxyDaemon.h"

//**************************************************************************
//	conductSession(int clientConnection, char authStr[], int serverSocket, char logging, struct NTLMSettings *theNTLMSettings)
//
//	split into two threads to conduct a two way HTTP session
//
//**************************************************************************
int conductSession(int clientConnection, char authStr[], int serverSocket, int logging, struct NTLMSettings *theNTLMSettings)
{
  if(theNTLMSettings)
  {
    if(establishNTLMAuthentication(clientConnection, &serverSocket, logging, theNTLMSettings))
      return -1;
    else if(logging)
      syslog(LOG_NOTICE, "Finished NTLM!");
  }
  
  pid_t pid;
  switch(pid = fork())			//spawn a new process to handle the request
  {
    case -1:						//trouble!!
      syslog(LOG_ERR, "Fatal Error. Unable to create new process: %m");
      close(clientConnection);
      exit(1);
    case 0:							//the child
      if( (authStr[0]!='\0' ?
           conductClientSide(clientConnection, authStr, serverSocket, logging) :
           conductClientSideDirectly(clientConnection, serverSocket, logging)) < 0)
      {
        if(logging)
          syslog(LOG_NOTICE, "Client closed ungracefully. Killing session processes.");
        kill(getppid(), SIGKILL);
        exit(EXIT_FAILURE);
      }
      else
      {
        if(logging)
          syslog(LOG_NOTICE, "Client closed connection, killing session processes.");
        kill(getppid(), SIGKILL);	//the client closed the connection, so kill the server connection as well
        exit(EXIT_SUCCESS);
      }
      
    default:						//the parent
      if (conductServerSide(clientConnection, serverSocket, logging) < 0)
      {
        if(logging)
          syslog(LOG_NOTICE, "Server closed ungracefully. Killing session processes.");
        kill(pid, SIGKILL);
        exit(EXIT_FAILURE);
      }
      else
      {
        if(logging)
          syslog(LOG_NOTICE, "Server closed connection, killing session processes.");
        kill(pid, SIGKILL);	//the server closed the connection, so kill the client connection as well
        exit(EXIT_SUCCESS);
      }      
  }
  close(serverSocket);
  close(clientConnection);
  return 1;
}

//**************************************************************************
//	int handleConnection(int clientSocket)
//
//	accept a connection on the clientSocket
//
//**************************************************************************
int handleConnection(int clientSocket)
{
  int connection;
  unsigned int sinSize = sizeof(struct sockaddr_in);
  struct sockaddr_in clientAddr;
  
  if((connection = accept(clientSocket, (struct sockaddr*) &clientAddr, &sinSize)) < 0)		//wait for connection
  {
    syslog(LOG_ERR, "Fatal Error. Unable to accept connection on listen socket: %m");
    return -1;
  }
  else
  {
    //syslog(LOG_NOTICE, "Accepted connection from:");
    //syslog(LOG_NOTICE, inet_ntoa(clientAddr.sin_addr));
    return connection;
  }
}

//**************************************************************************
//	int establishServerSide(char *hostname, unsigned short portnum, char direct=0)
//
//	socket and connect to server
//
//**************************************************************************
int establishServerSide(char *hostname, unsigned short portnum)
{
  //if hostname is NULL, these values will be used instead
  static char lastServerConnected[256] = "";
  static unsigned short lastPortConnected=0;
  
  struct sockaddr_in talkSockAddr;
  struct hostent     *hp;
  int talkSocket;

  if((hp = gethostbyname(hostname ? hostname : lastServerConnected)) == NULL)
  {
    errno = ECONNREFUSED;	//if we can't resolve the hostname, return -1.
    return -1;
  }

  memset(&talkSockAddr, 0, sizeof(struct sockaddr_in));
  memcpy((char *)&talkSockAddr.sin_addr, hp->h_addr, hp->h_length); /* set address */
  talkSockAddr.sin_family = hp->h_addrtype;
  talkSockAddr.sin_port = htons((u_short) (hostname ? portnum : lastPortConnected));

  if((talkSocket = socket(hp->h_addrtype,SOCK_STREAM,0)) < 0)		//establish talker socket
  {
    syslog(LOG_ERR, "Fatal Error. Unable to establish talker socket: %m");
    return -1;
  }
  if(connect(talkSocket, (struct sockaddr *)&talkSockAddr, sizeof(struct sockaddr_in)) < 0)		//connect to talker socket
  {
    close(talkSocket);
    syslog(LOG_ERR, "Fatal Error. Unable to connect to talker socket: %m");
    return -1;
  }
  
  if(hostname)
  {
    strcpy(lastServerConnected, hostname);
    lastPortConnected = portnum;
  }
  
  return talkSocket;
}

//**************************************************************************
//	int establishClientSide(int port, int maxpend)
//
//	socket and bind to the client
//
//**************************************************************************
int establishClientSide(int port, int maxpend, char external)
{
  int listenSocket;
  struct sockaddr_in listenSockAddr;
  int yes=1;

  if((listenSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)	//open up a internet socket
  {
    syslog(LOG_ERR, "Fatal Error. Unable to establish listener socket: %m");
    return -1;
  }
  
  memset(&listenSockAddr, 0, sizeof(struct sockaddr_in));	//clear the struct
  listenSockAddr.sin_family = AF_INET;
  listenSockAddr.sin_port = htons(port);
  listenSockAddr.sin_addr.s_addr = external ? INADDR_ANY : inet_addr("127.0.0.1");

  // lose the pesky "Address already in use" error message
  if (setsockopt(listenSocket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1)
    syslog(LOG_ERR, "Unable to set socket options. Bit strange that. Port may be blocked. Errno: %m");
  
  if(bind(listenSocket, (struct sockaddr *) &listenSockAddr, sizeof(struct sockaddr)) < 0)
  {
    close(listenSocket);
    syslog(LOG_ERR, "Fatal Error: unable to bind listen socket. Port probably has not been released. Wait a minute or so and try again. Errno: %m");
    return -1;
  }

  if(listen(listenSocket, maxpend) < 0)		//make it a listen port with maxpend max pending connections
  {
    close(listenSocket);
    syslog(LOG_ERR, "Fatal Error. Unable to establish listen socket: %m");
    return -1;
  }
  
  return listenSocket;
}

//**************************************************************************
//	void conductClientSide(int clientConnection, char authStr[], int serverSocket, char logging)
//
//	loop continuously, pushing data from the client to the server
//
//**************************************************************************
#define CR1st 1
#define LF1st 2
#define CR2nd 3
#define LF2nd 4

int conductClientSide(int clientConnection, char authStr[], int serverSocket, int logging)
{
  while(1)
  {
    int recvBufSize=0, bytesSent, i, j, connectionClosed=0, endHeader=0;
    char listenBuf[INCOMING_BUF_SIZE+strlen(authStr)+1], *tempBuf=NULL;
    char debugBuf[81];
    int CRLFCRLF=0; //value to determine if the CRLFCRLF has been seen yet
    
    while((recvBufSize = recv(clientConnection, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)  //retrieve the data on the listen socket
    {
      if(endHeader && (//first time we enter this, we know it is a header and don't need to do this checking. Otherwise...
         (listenBuf[0]=='G' && listenBuf[1]=='E' && listenBuf[2]=='T') ||
         (listenBuf[0]=='C' && listenBuf[1]=='O' && listenBuf[2]=='N' && listenBuf[3]=='N' && listenBuf[4]=='E' && listenBuf[5]=='C' && listenBuf[6]=='T') ||
         (listenBuf[0]=='P' && listenBuf[1]=='O' && listenBuf[2]=='S' && listenBuf[3]=='T') ||
         (listenBuf[0]=='O' && listenBuf[1]=='P' && listenBuf[2]=='T' && listenBuf[3]=='I' && listenBuf[4]=='O' && listenBuf[5]=='N' && listenBuf[6]=='S') ||
         (listenBuf[0]=='H' && listenBuf[1]=='E' && listenBuf[2]=='A' && listenBuf[3]=='D') ||
         (listenBuf[0]=='P' && listenBuf[1]=='U' && listenBuf[2]=='T') ||
         (listenBuf[0]=='D' && listenBuf[1]=='E' && listenBuf[2]=='L' && listenBuf[3]=='E' && listenBuf[4]=='T' && listenBuf[5]=='E') ||
         (listenBuf[0]=='T' && listenBuf[1]=='R' && listenBuf[2]=='A' && listenBuf[3]=='C' && listenBuf[4]=='E'))
         )//list of headers above from RFC2616, pg 24
        endHeader=0; //looks like a new header

//      syslog(LOG_NOTICE, "just recv'ed");      
      //Right, we've got some data, check to see if it has a CRLFCRLF
      if(!endHeader)
      {
        for(i=0; i<recvBufSize; i++)
        {
          if(CRLFCRLF == CR2nd && listenBuf[i]==LF) //found it!
          {
            CRLFCRLF = LF2nd;
            //we've found the end of the headers! Lets insert our little auth string.
            tempBuf = (char*) malloc((recvBufSize-i-1)*sizeof(char));
            memcpy(tempBuf, &listenBuf[i+1], recvBufSize-i-1);
            if (i==0)
            {
              memcpy(listenBuf + i, authStr, strlen(authStr));
              memcpy(listenBuf + i+strlen(authStr), tempBuf, recvBufSize-i-1);
            }
            else
            {
              memcpy(listenBuf + i-1, authStr, strlen(authStr));
              memcpy(listenBuf + i-1+strlen(authStr), tempBuf, recvBufSize-i-1);
            }              
            free(tempBuf);
            recvBufSize += strlen(authStr)-2;	//-2 for the CRLF which gets taken off the old end of headers
            endHeader=1;
            break;
          }
          else if(CRLFCRLF == LF1st && listenBuf[i]==CR)
          {
            CRLFCRLF = CR2nd;
            if(i==recvBufSize-1)	//then damn, looks like the second CRLF crosses the buffer limit.
              recvBufSize--;		//We're going to have to assume another LF is coming, and make sure we don't print the CR.
          }
          else if(CRLFCRLF == CR1st && listenBuf[i]==LF)
            CRLFCRLF = LF1st;
          else if(listenBuf[i]==CR)
            CRLFCRLF = CR1st;
          else
            CRLFCRLF = 0;
        }

        if(logging == LOGGING)
        {
          logging=0;	//only make a log entry once per connection
          i=0; j=0;
          while(i<80 && i<recvBufSize && listenBuf[i] != '\r' && listenBuf[i] != '\n')
          {
            if(listenBuf[i] >= ' ' && listenBuf[i] <= '~') //is a legit printable character
            {
              if(listenBuf[i]=='%') //we must escape it!
                debugBuf[j++] = '%';
              debugBuf[j++] = listenBuf[i];
            }
            i++;
          }
          debugBuf[i] = '\0';
          if(i>4)
            syslog(LOG_NOTICE, debugBuf);
        }
      }
      
      //here's a change: the send has moved inside the recv loop,
      //meaning we send the data _as_ we get it, rather than at the end
      //removes _lots_ of complexity associated with parsing the data as it came through
      //we are much more transparent now
      bytesSent=0;
      while(bytesSent<recvBufSize)
      {
        if((bytesSent += send(serverSocket, &listenBuf[bytesSent], recvBufSize-bytesSent, 0)) < 0)
        {
          syslog(LOG_NOTICE, "Couldn't send to talk connection: %m");
          return -1;
        }
//      syslog(LOG_NOTICE, "just sent this");
//      syslog(LOG_NOTICE, listenBuf);
      }
      if(logging == TESTING)
        logClientToServer(listenBuf, bytesSent);
    }
    
    if(recvBufSize==0)	//connection has been closed
      connectionClosed = 1;
    else //recvBufSize<0 - an error occured
    {
      if(errno==54) //that's the connection reset by peer error. Strangely, IE seems to do it all the time. I can't see why. RFC2616, Ch8.1 has the details on persistent connections, and I can't see why the connection wouldn't be dropped gracefully instead of this 'forceful drop by the server' we see.
      {
//          syslog(LOG_NOTICE, "Connection reset by peer, closing connection.");
        close(clientConnection);
        close(serverSocket);
      }
      else
        syslog(LOG_NOTICE, "Odd packet received. Ignoring. Errno: %m");
      
      return -1;
    }
    
    if(connectionClosed)
    {
//      syslog(LOG_NOTICE, "Connection closed by client.");
    
      close(clientConnection);
      close(serverSocket);
      return 0;	//there is nothing more we can do, no client to talk to!
    }
  }
  return 1;	//should be unreachable of course
}

//**************************************************************************
//	int conductClientSideDirectly(int clientConnection, int serverSocket, char logging)
//
//	loop continuously, pushing data from the client to the server
//
//**************************************************************************
int conductClientSideDirectly(int clientConnection, int serverSocket, int logging)
{
  int recvBufSize=0, bytesSent, directed=0;
  char listenBuf[INCOMING_BUF_SIZE+1];

  if(logging)
    syslog(LOG_NOTICE, "Handling a direct connection");
  
  while((recvBufSize = recv(clientConnection, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)  //retrieve the data on the listen socket
  {
    if(!directed)
    {
      int i, startOfAddress, endOfAddress;
      for(i=3; i<recvBufSize; i++)
      {
        if(listenBuf[i]==':')
        {
          startOfAddress=i;
          while(listenBuf[startOfAddress-1]!=' ')
            startOfAddress--;
          endOfAddress=i+3;
          while(listenBuf[endOfAddress]!='/')
            endOfAddress++;
          int j;
          for(i=startOfAddress, j=endOfAddress; j<recvBufSize; i++, j++)
            listenBuf[i] = listenBuf[j];
          recvBufSize-=(endOfAddress-startOfAddress);
          directed=1;
          break;
        }
        else if(listenBuf[i]=='/' || listenBuf[i]==CR || listenBuf[i]==LF)
        {
          directed=1;
          break;
        }
      }
    }
          
    bytesSent=0;
    while(bytesSent<recvBufSize)
    {
      if((bytesSent += send(serverSocket, &listenBuf[bytesSent], recvBufSize-bytesSent, 0)) < 0)
      {
        if(logging)
          syslog(LOG_NOTICE, "Couldn't send direct to server: %m");
        return -1;
      }
    }
    if(logging == TESTING)
      logClientToServer(listenBuf, recvBufSize);
  }
  if(recvBufSize==0)	//connection has been closed
  {
    close(clientConnection);
    close(serverSocket);
    return 0;	//there is nothing more we can do, no client to talk to!
  }
  else //recvBufSize<0 - an error occured
  {
    if(errno==54)
    {
      close(clientConnection);
      close(serverSocket);
    }
    else if(logging)
      syslog(LOG_NOTICE, "Odd packet received direct from server. Ignoring. Errno: %m");
    
    return -1;
  }
}

//**************************************************************************
//	int conductServerSide(int clientConnection, int serverSocket, char logging)
//
//	loop continuously, pushing data from the server to the client
//
//**************************************************************************
int conductServerSide(int clientConnection, int serverSocket, int logging)
{
  while(1)
  {
    int recvBufSize;
    char listenBuf[INCOMING_BUF_SIZE+1];
    
    while((recvBufSize = recv(serverSocket, listenBuf, INCOMING_BUF_SIZE, 0)) > 0)
    {
      int sentChars=0;
//      listenBuf[recvBufSize] = '\0';
//      syslog(LOG_NOTICE, "About to send back data");
//      syslog(LOG_NOTICE, listenBuf);
      while(sentChars<recvBufSize)
      {
        if((sentChars+=send(clientConnection, &listenBuf[sentChars], recvBufSize-sentChars, 0)) < 0)
        {
          if(logging)
            syslog(LOG_NOTICE, "Couldn't send to listen connection: %m");
          close(serverSocket);
          close(clientConnection);
          return -1;
        }
      }
      if(logging == TESTING)
        logServerToClient(listenBuf, recvBufSize);
    }
    
    if(recvBufSize < 0)
    {
      if(logging)
        syslog(LOG_NOTICE, "Unexpected closure of server socket: %m");
      close(serverSocket);
      close(clientConnection);
      return -1;
    }
    
//    syslog(LOG_NOTICE, "Connection closed by server.");
    close(serverSocket);
    close(clientConnection);
    return 0;
  }
}
