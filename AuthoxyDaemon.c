/*
 *  AuthoxyDaemon.c
 *  Authoxy
 *
 *  Created by Heath Raftery on Tue Sep 17 2002.
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
#include "base64.h"

#include <curl/curl.h>
  
int main(int argc, char* argv[])
{  
  char usingNTLM=0;  //are we using NTLM?
  if(argc == 8)
    usingNTLM=0;
  else if(argc == 10)
    usingNTLM=1;
  else
  {
    syslog(LOG_ERR, "Fatal Error: incorrect argument count for authoxyd. Ensure there are no old copies of Authoxy installed.");
    return 1;
  }

  signal(SIGCHLD, fireman);
  daemon(0, 0);
  //write our new PID to file (since it will be different to the one we started with)
  mode_t oldMask = umask(0);  //set new file mode to 0666 (read/write by everyone)
  FILE *f1 = fopen(AUTHOXYD_PID_PATH, "w");
  if(f1)
  {
    fprintf(f1, "%d", getpid());
    fclose(f1);    
  }
  //also write the port we are using to a file
  FILE *f2 = fopen(AUTHOXYD_PORT_PATH, "w");
  if(f2)
  {
    fprintf(f2, "%d", ARG_LPORT);
    fclose(f2);    
  }
  if(ARG_TEST)
  {
    FILE *f = fopen(AUTHOXYD_TEST_PATH, "w");
    if(f)
    {
      fprintf(f, "Test connection for authoxyd has begun.\n");
      fclose(f);
    }
  }
  umask(oldMask); //set it back
  
  int clientSocket;
  char *authStr;
  JSFunction *compiledPAC;
  struct NTLMSettings theNTLMSettings;

  if(usingNTLM)
  {
    authStr = (char *) malloc(3);
    strcpy(authStr, CRLF);
    
    char *un=NULL, *pw=NULL;
    if(decodePassKey(ARG_AUTH, &un, &pw))
    {
      //decode was unsuccessful
      syslog(LOG_ERR, "Fatal Error: unable to decode authorization string.");
      return 1;
    }
    theNTLMSettings.username = un;
    theNTLMSettings.password = pw;
    theNTLMSettings.domain = ARG_DOMAIN;
    theNTLMSettings.host = ARG_HOST;
  }
  else
  {
    authStr = (char *) malloc( (27+strlen(ARG_AUTH)+2+2+1) * sizeof(char) );	//thats the field header the auth string, two CRLF's and a sentinal

    strcpy(authStr, "Proxy-Authorization: Basic ");
    strcat(authStr, ARG_AUTH);
    strcat(authStr, CRLF);
    strcat(authStr, CRLF);
  }
  
  JSContext *cx=NULL;
  if(ARG_AUTO)
  {
    if(!(rt = JS_NewRuntime(1L * 1024L * 1024L)))
      return 1;
    if(!(cx = JS_NewContext(rt, 4L * 1024L)))
      return 1;
    global = JS_NewObject(cx, &global_class, NULL, NULL);
    JS_InitStandardClasses(cx, global);
    
    compiledPAC = compilePAC(cx, ARG_ADD);
    if(!compiledPAC)
      return 1;
  }
  else
    compiledPAC = NULL;
//ARG_LPORT is local port number, MAX_PEND is max number of pending connections, ARG_EXTERN is true if external connections are allowed
  if( (clientSocket = establishClientSide(ARG_LPORT, MAX_PEND, ARG_EXTERN)) < 0)
    return 1;

  if(ARG_LOGTEST != TESTING)
    syslog(LOG_NOTICE, "Authoxy has started successfully");
  else
    syslog(LOG_NOTICE, "Authoxy started in test mode. Full transcript will be written to /tmp/authoxy.test");
      
  //right, client socket is setup, the fun begins...
  int run = 1;
  while(run)	//enter an endless loop, handling requests
  {
    if(ARG_TEST) // spawn a process to make a web request
    {
      switch(fork())
      {
        case -1:						//trouble!!
          syslog(LOG_ERR, "Fatal Error. Unable to create new process: %m");
          close(clientSocket);
          exit(EXIT_FAILURE);
        case 0:             //the child
          close(clientSocket);
          //perform a web request
          CURL *myCurl = curl_easy_init();
          if(!myCurl)
          {
            syslog(LOG_ERR, "Unable to initialise curl library. Something is terribly wrong!");
            exit(EXIT_FAILURE);
          }

          char proxyAdd[16];
          strcpy(proxyAdd, "127.0.0.1:");
          strcpy(&proxyAdd[10], ARG_LPORT_STR);
          char errorBuf[CURL_ERROR_SIZE];
          
          curl_easy_setopt(myCurl, CURLOPT_NOPROGRESS, 1);	//turn off progress indication
          curl_easy_setopt(myCurl, CURLOPT_PROXY, proxyAdd);
          curl_easy_setopt(myCurl, CURLOPT_URL, "http://www.hrsoftworks.net/TestConnection.html");
          curl_easy_setopt(myCurl, CURLOPT_ERRORBUFFER, errorBuf);
          if(curl_easy_perform(myCurl))	//download
            syslog(LOG_ERR, "Failed to fetch URL: %s", errorBuf);
          else
          {
            long resultCode;
            curl_easy_getinfo(myCurl, CURLINFO_RESPONSE_CODE, &resultCode);
            if(resultCode == 200) //Success
              syslog(LOG_NOTICE, "Successfully fetched URL.");
            else if(resultCode == 407)  //Proxy authentication required
              syslog(LOG_ERR, "Failed to fetch URL. Proxy authentication rejected.");
            else
              syslog(LOG_ERR, "Failed to fetch URL. Server returned result code: %d", resultCode);
          }
          curl_easy_cleanup(myCurl);	//clean up after ourselves
          
          exit(EXIT_SUCCESS);

        //the parent will just continue on
      }
    }
    
    int clientConnection;
    if((clientConnection = handleConnection(clientSocket)) < 0)
    {
      if (errno == EINTR)	//apparently this may happen, and we just try again
        continue;					//otherwise we have problems...
      syslog(LOG_ERR, "Fatal Error. Unable to handle listening connection: %m");
      close(clientConnection);
      close(clientSocket);
      return 1;
    }
    
    switch(fork())			//spawn a new process to handle the request
    {
      case -1:						//trouble!!
        syslog(LOG_ERR, "Fatal Error. Unable to create new process: %m");
        close(clientConnection);
        close(clientSocket);
        exit(EXIT_FAILURE);
      case 0:							//the child
        close(clientSocket);	//the child doesn't need this
        if(ARG_AUTO)
          performDaemonConnectionWithPACFile(compiledPAC, ARG_ADD, ARG_RPORT, clientConnection, authStr, usingNTLM, &theNTLMSettings, ARG_LOGTEST);
        else
          performDaemonConnection(ARG_ADD, ARG_RPORT, clientConnection, authStr, usingNTLM, &theNTLMSettings, ARG_LOGTEST);
      
      default: //the parent, so continue on our merry way
        close(clientConnection);
        
        if(!ARG_TEST)
          continue;
        else  //we're testing, so wait for the child to finish its business and then quit
        {
          //Initialise result in case the parent is killed by the child and therefore doesn't return a result.
          //This happens in the successful case when the client closes the connection after completing its request.
          int result = EXIT_SUCCESS;
          wait(&result);
          if(result == EXIT_SUCCESS)
            syslog(LOG_NOTICE, "No connection problems. Check the log at %s if you experience difficulties.", AUTHOXYD_TEST_PATH);
          else
            syslog(LOG_NOTICE, "Connection failed. A log of the communication has been written to %s", AUTHOXYD_TEST_PATH);
          run = 0;  //stop running
          break;
        }
    }
  }

  //these lines are actually unlikely to be called, except under exceptional failures
  close(clientSocket);

  free(authStr);
  
  if(ARG_AUTO)
  {
    JS_DestroyContext(cx);
    JS_DestroyRuntime(rt);
  }

  return 0;
}

void performDaemonConnection(char *argAdd, int argRPort, int clientConnection, char *authStr, char usingNTLM, struct NTLMSettings *theNTLMSettingsPtr, int logging)
{
  int serverSocket;
  
  if( (serverSocket = establishServerSide(argAdd, argRPort)) < 0 )
  {
    syslog(LOG_NOTICE, "Couldn't open connection to proxy server: %m");
    close(clientConnection);
    exit(EXIT_FAILURE);
  }
  else if(conductSession(clientConnection, authStr, serverSocket, logging, usingNTLM ? theNTLMSettingsPtr : NULL) < 0)
  {
    close(clientConnection);
    close(serverSocket);
    exit(EXIT_FAILURE);
  }
  else
    exit(EXIT_SUCCESS);
}

void performDaemonConnectionWithPACFile(JSFunction *compiledPAC, char *argADD, int argRPort, int clientConnection, char *authStr, char usingNTLM, struct NTLMSettings *theNTLMSettingsPtr, int logging)
{
  int serverSocket;
  
  char proxyAdd[PEEK_BUF_SIZE];
  int proxyPort;
  char *result;
  char *requestURL, requestHost[PEEK_BUF_SIZE];
  int requestPort;
  
  //take a peek at the data from the client to find out the host requested
  int recvBufSize=0, i=0, j=0;
  char peekBuf[PEEK_BUF_SIZE+1];
  
  recvBufSize = recv(clientConnection, peekBuf, PEEK_BUF_SIZE, MSG_PEEK);	//peek at the data on the listen socket
  if(recvBufSize>0)
  {
    char authority=0; //in a CONNECT request, the Request-URI is an "authority". That is, there is no ....:// only the server name
    if(bufferMatchesStringAtIndex(peekBuf, "CONNECT", 0))
      authority=1;
    while(i<recvBufSize && peekBuf[i]!=' ')
      i++;
    requestURL = &peekBuf[i];                                             //extract the request URL
    i++;
    while(i<recvBufSize && peekBuf[i]!=' ')
      i++;
    peekBuf[i]='\0';                                                      //terminate the request URL
    for(i=0; i<strlen(requestURL)-3; i++)
    {
      if(authority && requestURL[i]!=' ')
        break;
      else if(requestURL[i]==':' && requestURL[i+1]=='/' && requestURL[i+2]=='/')//find the start of the request host
      {
        i+=3;
        break;
      }
    }
    for(j=i; j<strlen(requestURL)-1; j++)
    {
      if(requestURL[j]==':' || requestURL[j]=='/')                          //find the end of the request host
        break;
    }
    strncpy(requestHost, &requestURL[i], j-i);                              //extract the request host from the request URL
    requestHost[j-i]='\0';                                                  //and terminate it
    if(requestURL[j]==':')                                                  //then there is port information which we will need if a DIRECT connection is requested
    {
      int portIndex=j+1;
      requestPort = requestURL[portIndex++]-'0';
      while(isdigit(requestURL[portIndex]))
      {
        requestPort*=10;
        requestPort+=(requestURL[portIndex++]-'0');
      }
    }
    else
      requestPort=80; //that's the default if no port is specified

    JSContext *threadcx=NULL;
    if(!(threadcx = JS_NewContext(rt, 4L * 1024L)))
    {
      syslog(LOG_ERR, "Unable to create thread context");
      exit(EXIT_FAILURE);
    }
    if(!(result = executePAC(threadcx, compiledPAC, requestURL, requestHost)))
      exit(EXIT_FAILURE);
    JS_DestroyContext(threadcx);
    //Okay, PAC file has been executed. We need to iterate through the result string trying to contact the servers provided.
    char *resultIter = result;
    char direct;  //bool value. DIRECT connection?
    do
    {
      if(*resultIter=='\0')                                                   //end of result string
      {
        syslog(LOG_NOTICE, "Exhausted PAC file server list and still failed to make a connection. Giving up on connection.");
        close(clientConnection);
        exit(EXIT_FAILURE);
      }      
      else if(*resultIter=='D')                                               //Direct connection.
      {
        strcpy(proxyAdd, requestHost);                                        //In a direct connection we need to contact the server directly
        proxyPort = requestPort;                                              //Instead of using 0 as a flag, we now respect the port request
        direct = 1;
      }
      else if(*resultIter=='P')                                               //Proxy connection
      {
        int i, j;
        for(i=0, j=6; resultIter[j]!=':'; i++, j++)
          proxyAdd[i] = resultIter[j];
        proxyAdd[i] = '\0';
        for(proxyPort = 0, j++; isdigit(resultIter[j]); j++)
        {
          proxyPort *= 10;
          proxyPort += (resultIter[j]-'0');
        }
        direct = 0;
      }
      else                                                                    //maybe SOCKS server or corrupted result string
      {
        syslog(LOG_ERR, "Unsupported connection method requested. Giving up on connection.");
        syslog(LOG_NOTICE, result);
        exit(EXIT_FAILURE);
      }
      while(*resultIter!=';' && *resultIter!='\0')
        resultIter++;
      while(*resultIter!='D' && *resultIter!='P' && *resultIter!='\0')
        resultIter++;
      
//      syslog(LOG_NOTICE, "About to try %s:%d, direct:%d", proxyAdd, proxyPort, direct);
    }
    while( (serverSocket = establishServerSide(proxyAdd, proxyPort)) < 0 );
    free(result);
    
    if(conductSession(clientConnection, (direct ? "" : authStr), serverSocket, logging, (!direct && usingNTLM) ? theNTLMSettingsPtr : NULL) < 0)
    {
      close(clientConnection);
      close(serverSocket);
      exit(EXIT_FAILURE);
    }
    else
      exit(EXIT_SUCCESS);
  }
  else
  {
    syslog(LOG_ERR, "Couldn't peek at client request for auto config script input: %m");
    exit(EXIT_FAILURE);
  }
}


/* as children die we should get catch their returns or else we get
 * zombies, A Bad Thing.  fireman() catches falling children.
 */
void fireman(int sig)
{
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
}

int bufferMatchesStringAtIndex(const char *buffer, const char *string, int index)
{
  int i;
  int len = strlen(string);
  for(i=0; i<len; i++)
    if(buffer[index+i] != string[i])
      return 0;
  return 1;
}

void logClientToServer(char *buf, int bufSize)
{
  mode_t oldMask = umask(0);
  FILE *f = fopen(AUTHOXYD_TEST_PATH, "a");
  if(f)
  {
    fprintf(f, "\n\n>>>\n\n");
    buf[bufSize] = '\0';
    fprintf(f, "%s", buf);
    fclose(f);
  }
  umask(oldMask);  
}

void logServerToClient(char *buf, int bufSize)
{
  mode_t oldMask = umask(0);
  FILE *f = fopen(AUTHOXYD_TEST_PATH, "a");
  if(f)
  {
    fprintf(f, "\n\n<<<\n\n");
    buf[bufSize] = '\0';
    fprintf(f, "%s", buf);
    fclose(f);
  }
  umask(oldMask);
}
