/*
 *  base64.c
 *  Authoxy
 *
 *  Created by Heath Raftery on Thu Sep 19 2002.
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

#include "base64.h"

//encode dictionary
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//decode dictionary
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

//encode a username and password, returning pointer to _malloced_ char array
//caller's onus on freeing return value and arguments
char* encodePassKey(char username[], char password[])
{
  unsigned char in[3], out[4];
  char colon[] = ":", *inString, *outString;
  int i, inc=0, outc=0, len;

  inString = (char *) malloc( (strlen(username)+strlen(colon)+strlen(password)+1)*sizeof(char));
  //outString is 133% the size of inString.
  outString = (char *) malloc( ((strlen(username)+strlen(colon)+strlen(password)+1)*sizeof(char)*4)/3);
  
  strcpy(inString, username);
  strcat(inString, colon);
  strcat(inString, password);
  
  while(inc == 0 || inString[inc-1] != '\0')
  {
    len = 0;
    for(i = 0; i < 3; i++)
    {
      in[i] = inString[inc++];
      if(inString[inc-1] != '\0')
        len++;
      else
        in[i] = 0;
    }
  
    if(len)
    {
      encodeBlock(in, out, len);
      for(i = 0; i < 4; i++)
        outString[outc++] = out[i];
    }
  }
  outString[outc] = '\0';
  
  free(inString);
  
  return outString;
}

//encode 3 8-bit binary bytes as 4 '6-bit' characters
void encodeBlock(unsigned char in[3], unsigned char out[4], int len)
{
  out[0] = cb64[ in[0] >> 2 ];
  out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4) ];
  out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6) ] : '=');
  out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3F ] : '=');
}

// decode a encoded string into a username and password char array
// return 0 if successful, number of characters decoded +1 otherwise
// caller's onus on freeing encoded, username and password
int decodePassKey(char *encoded, char *username[], char *password[])
{
  unsigned char in[4], out[3], v;
  char *decoded, *colon;
  int i, len, enc = 0, dec = 0;

  decoded = (char *) malloc( strlen(encoded) * sizeof(char) );
  
  while(enc == 0 || encoded[enc-1] != '\0')
  {
    for(len = 0, i = 0; i < 4 && (enc == 0 || encoded[enc-1]!='\0'); i++)
    {
      v = 0;
      while((enc == 0 || encoded[enc-1]!='\0') && v == 0 )
      {
        v = encoded[enc++];
        v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
        if(v)
          v = (unsigned char) ((v == '$') ? 0 : v - 61);
      }
      if(encoded[enc-1]!='\0')
      {
        len++;
        if(v)
          in[i] = (unsigned char) (v - 1);
      }
      else
        in[i] = 0;
    }
    if(len)
    {
      decodeBlock(in, out);
      for( i = 0; i < len - 1; i++ )
        decoded[dec++] = out[i];
    }
  }
  
  decoded[dec] = '\0';
  dec++;	//so dec is true if no letters were decoded

  if( (colon = strchr(decoded, ':')) )
  {
    *colon = '\0';
    *username = (char *) malloc(colon - decoded + 1);
    strcpy(*username, decoded);
    *password = (char *) malloc(decoded + dec - colon);
    colon++;
    strcpy(*password, colon);
    dec = 0;
  }
  
  free(decoded);
  return dec;
}

// decode 4 '6-bit' characters into 3 8-bit binary bytes
void decodeBlock( unsigned char in[4], unsigned char out[3] )
{   
  out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
  out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
  out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

// encode an arbitrary string
char *encodeString(char *inString, int *length)
{
  unsigned char in[3], out[4];
  char *outString=NULL;
  int i, inc=0, outc=0, len;
  
  //outString is 133% the size of inString.
  outString = (char *)malloc( 4 * ((*length + 2)/3));  //+2 allows rounding up to the next multiple of 3 to allow enough groups of 4
    
  while(inc<=*length)
  {
    len = 0;
    for(i = 0; i < 3; i++)
    {
      in[i] = inString[inc++];
      if(inc<=*length)
        len++;
      else
        in[i] = 0;
    }
    
    if(len)
    {
      encodeBlock(in, out, len);
      for(i = 0; i < 4; i++)
        outString[outc++] = out[i];
    }
  }
  *length=outc;  
  return outString;  
}

// decode an arbitrary string
char* decodeString(char *inString, int *length)
{
  unsigned char in[4], out[3], v;
  char *decoded;
  int i, len, enc = 0, dec = 0;
  
  decoded = (char *)malloc( (*length) * sizeof(char) );
  
  while(enc<=*length)
  {
    for(len = 0, i = 0; i < 4 && enc<=*length; i++)
    {
      v = 0;
      while(enc<=*length && v == 0 )
      {
        v = inString[enc++];
        v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
        if(v)
          v = (unsigned char) ((v == '$') ? 0 : v - 61);
      }
      if(enc<=*length)
      {
        len++;
        if(v)
          in[i] = (unsigned char) (v - 1);
      }
      else
        in[i] = 0;
    }
    if(len)
    {
      decodeBlock(in, out);
      for(i = 0; i < len - 1; i++)
        decoded[dec++] = out[i];
    }
  }
  *length = dec;
  
  return decoded;
}