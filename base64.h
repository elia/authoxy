/*
 *  base64.h
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

#include <stdlib.h>
#include <string.h>

char* encodePassKey(char username[], char password[]);
void encodeBlock(unsigned char in[3], unsigned char out[4], int len);
int decodePassKey(char encoded[], char *username[], char *password[]);
void decodeBlock( unsigned char in[4], unsigned char out[3] );
char* encodeString(char *inString, int *length);
char* decodeString(char *inString, int *length);