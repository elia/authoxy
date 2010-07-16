/*
 *  jsInterface.c
 *  Authoxy
 *
 *  Created by Heath Raftery on Fri Jan 2 2004.
 *  Copyright (c) 2003, 2004 HRSoftWorks. All rights reserved.
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

JSBool ResolveInC(JSContext *cx, JSObject *obj, uintN argc, jsval *argv, jsval *rval);

//these are the extra javascript routines for Pac support. Ugly eh?
//from: http://lxr.mozilla.org/seamonkey/source/netwerk/base/src/nsProxyAutoConfig.js
//note that code, as long with the js*.h files, are covered by the MPL: http://www.mozilla.org/MPL/
const char pacUtils[]="var dnsResolveCachedHost = null;\nvar dnsResolveCachedIp = null;\n\n// wrapper for dns.resolve to catch exception on failure\nfunction dnsResolve(host) {\n    if (host == dnsResolveCachedHost) {\n        return dnsResolveCachedIp;\n    }\n    try {\n        dnsResolveCachedIp = ResolveInC(host);\n        dnsResolveCachedHost = host;\n    }\n    catch (e) {\n        dnsResolveCachedIp = null;\n        dnsResolveCachedHost = null;\n   }\n    return dnsResolveCachedIp;\n}\n\nfunction dnsDomainIs(host, domain) {\n    return (host.length >= domain.length &&\n            host.substring(host.length - domain.length) == domain);\n}\nfunction dnsDomainLevels(host) {\n    return host.split('.').length-1;\n}\nfunction convert_addr(ipchars) {\n    var bytes = ipchars.split('.');\n    var result = ((bytes[0] & 0xff) << 24) |\n                 ((bytes[1] & 0xff) << 16) |\n                 ((bytes[2] & 0xff) <<  8) |\n                  (bytes[3] & 0xff);\n    return result;\n}\nfunction isInNet(ipaddr, pattern, maskstr) {\n    var test = /^(\\d{1,4})\\.(\\d{1,4})\\.(\\d{1,4})\\.(\\d{1,4})$/(ipaddr);\n    if (test == null) {\n        ipaddr = dnsResolve(ipaddr);\n        if (ipaddr == null)\n            return false;\n    } else if (test[1] > 255 || test[2] > 255 || \n               test[3] > 255 || test[4] > 255) {\n        return false;    // not an IP address\n    }\n    var host = convert_addr(ipaddr);\n    var pat  = convert_addr(pattern);\n    var mask = convert_addr(maskstr);\n    return ((host & mask) == (pat & mask));\n    \n}\nfunction isPlainHostName(host) {\n    return (host.search('\\\\.') == -1);\n}\nfunction isResolvable(host) {\n    var ip = dnsResolve(host);\n    return (ip != null);\n}\nfunction localHostOrDomainIs(host, hostdom) {\n    if (isPlainHostName(host)) {\n        return (hostdom.search('/^' + host + '/') != -1);\n    }\n    else {\n        return (host == hostdom); //TODO check \n    }\n}\n var myIP;\nfunction myIpAddress() {\n    return (myIP) ? myIP : '127.0.0.1';\n}\nfunction shExpMatch(url, pattern) {\n   pattern = pattern.replace(/\\./g, '\\\\.');\n   pattern = pattern.replace(/\\*/g, '.*');\n   pattern = pattern.replace(/\\?/g, '.');\n   var newRe = new RegExp('^'+pattern+'$');\n   return newRe.test(url);\n}\nvar wdays = new Array('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT');\nvar monthes = new Array('JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC');\nfunction weekdayRange() {\n    function getDay(weekday) {\n        for (var i = 0; i < 6; i++) {\n            if (weekday == wdays[i]) \n                return i;\n        }\n        return -1;\n    }\n    var date = new Date();\n    var argc = arguments.length;\n    var wday;\n    if (argc < 1)\n        return false;\n    if (arguments[argc - 1] == 'GMT') {\n        argc--;\n        wday = date.getUTCDay();\n    } else {\n        wday = date.getDay();\n    }\n    var wd1 = getDay(arguments[0]);\n    var wd2 = (argc == 2) ? getDay(arguments[1]) : wd1;\n    return (wd1 == -1 || wd2 == -1) ? false\n                                    : (wd1 <= wday && wday <= wd2);\n}\nfunction dateRange() {\n    function getMonth(name) {\n        for (var i = 0; i < 6; i++) {\n            if (name == monthes[i])\n                return i;\n        }\n        return -1;\n    }\n    var date = new Date();\n    var argc = arguments.length;\n    if (argc < 1) {\n        return false;\n    }\n    var isGMT = (arguments[argc - 1] == 'GMT');\n\n    if (isGMT) {\n        argc--;\n    }\n    // function will work even without explict handling of this case\n    if (argc == 1) {\n        var tmp = parseInt(arguments[0]);\n        if (isNaN(tmp)) {\n            return ((isGMT ? date.getUTCMonth() : date.getMonth()) ==\ngetMonth(arguments[0]));\n        } else if (tmp < 32) {\n            return ((isGMT ? date.getUTCDate() : date.getDate()) == tmp);\n        } else { \n            return ((isGMT ? date.getUTCFullYear() : date.getFullYear()) ==\ntmp);\n        }\n    }\n    var year = date.getFullYear();\n    var date1, date2;\n    date1 = new Date(year,  0,  1,  0,  0,  0);\n    date2 = new Date(year, 11, 31, 23, 59, 59);\n    var adjustMonth = false;\n    for (var i = 0; i < (argc >> 1); i++) {\n        var tmp = parseInt(arguments[i]);\n        if (isNaN(tmp)) {\n            var mon = getMonth(arguments[i]);\n            date1.setMonth(mon);\n        } else if (tmp < 32) {\n            adjustMonth = (argc <= 2);\n            date1.setDate(tmp);\n        } else {\n            date1.setFullYear(tmp);\n        }\n    }\n    for (var i = (argc >> 1); i < argc; i++) {\n        var tmp = parseInt(arguments[i]);\n        if (isNaN(tmp)) {\n            var mon = getMonth(arguments[i]);\n            date2.setMonth(mon);\n        } else if (tmp < 32) {\n            date2.setDate(tmp);\n        } else {\n            date2.setFullYear(tmp);\n        }\n    }\n    if (adjustMonth) {\n        date1.setMonth(date.getMonth());\n        date2.setMonth(date.getMonth());\n    }\n    if (isGMT) {\n    var tmp = date;\n        tmp.setFullYear(date.getUTCFullYear());\n        tmp.setMonth(date.getUTCMonth());\n        tmp.setDate(date.getUTCDate());\n        tmp.setHours(date.getUTCHours());\n        tmp.setMinutes(date.getUTCMinutes());\n        tmp.setSeconds(date.getUTCSeconds());\n        date = tmp;\n    }\n    return ((date1 <= date) && (date <= date2));\n}\nfunction timeRange() {\n    var argc = arguments.length;\n    var date = new Date();\n    var isGMT= false;\n\n    if (argc < 1) {\n        return false;\n    }\n    if (arguments[argc - 1] == 'GMT') {\n        isGMT = true;\n        argc--;\n    }\n\n    var hour = isGMT ? date.getUTCHours() : date.getHours();\n    var date1, date2;\n    date1 = new Date();\n    date2 = new Date();\n\n    if (argc == 1) {\n        return (hour == arguments[0]);\n    } else if (argc == 2) {\n        return ((arguments[0] <= hour) && (hour <= arguments[1]));\n    } else {\n        switch (argc) {\n        case 6:\n            date1.setSeconds(arguments[2]);\n            date2.setSeconds(arguments[5]);\n        case 4:\n            var middle = argc >> 1;\n            date1.setHours(arguments[0]);\n            date1.setMinutes(arguments[1]);\n            date2.setHours(arguments[middle]);\n            date2.setMinutes(arguments[middle + 1]);\n            if (middle == 2) {\n                date2.setSeconds(59);\n            }\n            break;\n        default:\n          throw 'timeRange: bad number of arguments'\n        }\n    }\n\n    if (isGMT) {\n        date.setFullYear(date.getUTCFullYear());\n        date.setMonth(date.getUTCMonth());\n        date.setDate(date.getUTCDate());\n        date.setHours(date.getUTCHours());\n        date.setMinutes(date.getUTCMinutes());\n        date.setSeconds(date.getUTCSeconds());\n    }\n    return ((date1 <= date) && (date <= date2));\n}\n";


JSRuntime *rt;
JSObject *global;
JSClass global_class =
{
  "global", 0, JS_PropertyStub,JS_PropertyStub,JS_PropertyStub,JS_PropertyStub,
  JS_EnumerateStub,JS_ResolveStub,JS_ConvertStub,JS_FinalizeStub
};

#include <curl/curl.h>

size_t collectData(void *ptr, size_t size, size_t nmemb, void *stream);

JSFunction* compilePAC(JSContext *cx, char *pacURL)
{
  char **scriptHdl;
  scriptHdl = (char**)malloc(sizeof(char*));
  *scriptHdl=NULL;
  //initialise curl so we can download the pac file
  CURL *myCurl = curl_easy_init();
  if(!myCurl)
  {
    syslog(LOG_ERR, "Unable to initialise curl library. Something is terribly wrong!");
    return NULL;
  }
  curl_easy_setopt(myCurl, CURLOPT_NOPROGRESS, 1);	//turn of progress indication
  curl_easy_setopt(myCurl, CURLOPT_WRITEFUNCTION, collectData);	//turn of progress indication
//  curl_easy_setopt(myCurl, CURLOPT_WRITEDATA, scriptHdl);
  curl_easy_setopt(myCurl, CURLOPT_FILE, scriptHdl);
  curl_easy_setopt(myCurl, CURLOPT_URL, pacURL);	//URL of pac file to download

//  syslog(LOG_NOTICE, "About to perform curl");
  curl_easy_perform(myCurl);	//download the pac file and then,
  curl_easy_cleanup(myCurl);	//clean up after ourselves
//  syslog(LOG_NOTICE, "Performed curl");
  
  JSFunction *compiledFunc=NULL;
  if(*scriptHdl!=NULL)
  {
    char *script;
    script = *scriptHdl;
  /*
    char *script = "
      if (isPlainHostName(host)) return \"DIRECT\";
      else if (isInNet(host,\"127.0.0.1\",\"255.0.0.0\")) return \"DIRECT\";
      else if (isInNet(host,\"127.0.0.1\",\"255.0.0.0\")) return \"DIRECT\";
      else if (isInNet(host,\"134.148.0.0\",\"255.255.0.0\")) return \"DIRECT\";
      else if (isInNet(host,\"157.85.0.0\",\"255.255.0.0\")) return \"DIRECT\";
      else if (isInNet(host,\"203.1.29.0\",\"255.255.255.0\")) return \"DIRECT\";
      else if (isInNet(host,\"203.1.30.0\",\"255.255.255.0\")) return \"DIRECT\";
      else if (isInNet(host,\"203.1.32.0\",\"255.255.255.0\")) return \"DIRECT\";
      else if (isInNet(host,\"192.76.122.0\",\"255.255.255.0\")) return \"DIRECT\";
      else if (isInNet(host,\"192.82.161.0\",\"255.255.255.0\")) return \"DIRECT\";
      else if (shExpMatch(host,\"*.newcastle.edu.au\")) return \"DIRECT\";
      else if (shExpMatch(host,\"*.galegroup.com\")) return \"DIRECT\";
      else if (shExpMatch(host,\"*.gale.com\")) return \"DIRECT\";
      else if (shExpMatch(host,\"*.galenet.com\")) return \"DIRECT\";
      else if (shExpMatch(host,\"www.searchbank.com\")) return \"DIRECT\";
      else if (shExpMatch(host,\"www.ams.org\")) return \"DIRECT\";
      else if (shExpMatch(host,\"hermes.deetya.gov.au\")) return \"DIRECT\";
      else if (shExpMatch(host,\"www.blackwell-synergy.com\")) return \"DIRECT\";
      else if (shExpMatch(host,\"www.munksgaard-synergy.com\")) return \"DIRECT\";
      else     return \"PROXY vproxy-1.newcastle.edu.au:8080; PROXY vproxy-2.newcastle.edu.au:8080; DIRECT\";";
  */
  /*
    int functionIndex;
    for(functionIndex=0; functionIndex<strlen(script); functionIndex++)
      if(script[functionIndex]=='{')	//find the start of the function
        break;
    script = &script[functionIndex+1];	//we'll ignore everything before the first brace
    for(functionIndex=strlen(script)-1; functionIndex>0; functionIndex--)
      if(script[functionIndex]=='}')
        break;
    script[functionIndex]='\0';		//and everything after and including the last closing brace
  */
    int functionIndex, startFunction=0;
    for(functionIndex=0; functionIndex<strlen(script); functionIndex++)
    {
      if(strncmp("function FindProxyForURL", &script[functionIndex], 24) == 0 || strncmp("function\nFindProxyForURL", &script[functionIndex], 24) == 0)
      {
        startFunction=functionIndex;
        for(functionIndex+=24; functionIndex<strlen(script); functionIndex++)
          if(script[functionIndex]=='{')  //find the start of the function
            break;
        int i, j;
        for(i=startFunction, j=functionIndex+1; j<strlen(script); i++, j++)
          script[i]=script[j]; //remove the function's opening declaration
        script[i]='\0';
        break;
      }
    }
    int braceCount=1;
    for(functionIndex=startFunction; functionIndex<strlen(script); functionIndex++)
    {
      if(script[functionIndex]=='{')
        braceCount++;
      else if(script[functionIndex]=='}')
        if(--braceCount==0)
          break;
    }
    script[functionIndex]=' '; //and the last closing brace
    
    char combinedScript[strlen(pacUtils)+strlen(script)+1];
    strcpy(combinedScript, pacUtils);
    strcat(combinedScript, script);
    
    uintN lineno=0;
  
    const char arg1[] = "url", arg2[] = "host";
    const char *args[] = {arg1, arg2};
    compiledFunc = JS_CompileFunction(cx, global, "FindProxyForURL", 2, args, combinedScript, strlen(combinedScript), pacURL, lineno);
    
    if(!compiledFunc)
      syslog(LOG_ERR, "Compile error in %s: line %d", pacURL, lineno);
  
    JSFunction *myCFunc = JS_DefineFunction(cx, global, "ResolveInC", ResolveInC, 1, 0);
    if(!myCFunc)
      syslog(LOG_ERR, "Unable to define javascript C utility.");
  
    free(*scriptHdl);
  }
  else
  {
    syslog(LOG_ERR, "Unable to download pac file. Check the address.");
  }
  
  free(scriptHdl);
  
  return compiledFunc;
}

char* executePAC(JSContext *cx, JSFunction *compiledScript, const char *arg1, const char *arg2)
{
  jsval rval;
  JSString *jsArg1, *jsArg2;
  jsval args[2];
  JSString *str;

  jsArg1 = JS_NewStringCopyZ(cx, arg1);
  jsArg2 = JS_NewStringCopyZ(cx, arg2);
  args[0] = STRING_TO_JSVAL(jsArg1);
  args[1] = STRING_TO_JSVAL(jsArg2);

//  syslog(LOG_NOTICE, "Arg1: %s, Arg2: %s", arg1, arg2);
  if(JS_CallFunction(cx, global, compiledScript, 2, args, &rval) == JS_FALSE)
  {
    syslog(LOG_ERR, "Error in executing pac script");
    return NULL;
  }
  
  str = JS_ValueToString(cx, rval);
  char *result = (char *)malloc(JS_GetStringLength(str)+1);
  result = JS_GetStringBytes(str);
  
//  syslog(LOG_NOTICE, "script result: %s", JS_GetStringBytes(str));

  return result;//JS_GetStringBytes(str);
}

JSBool ResolveInC(JSContext *cx, JSObject *obj, uintN argc, jsval *argv, jsval *rval)
{
  struct hostent *hent;
  hent = gethostbyname(JS_GetStringBytes(JSVAL_TO_STRING(argv[0])));
  if(!hent)
  {
    syslog(LOG_NOTICE, "Unable to resolve address. h-errno: %s", hstrerror(h_errno));
    JSString *result = JS_NewString(cx, "0.0.0.0", 7);
    *rval = STRING_TO_JSVAL(result);
  }
  else
  {
    JSString *result = JS_NewString(cx, inet_ntoa(*((struct in_addr *)hent->h_addr_list[0])),
                                    strlen(inet_ntoa(*((struct in_addr *)hent->h_addr_list[0]))));
    *rval = STRING_TO_JSVAL(result);
  }
  return JS_TRUE;
}

size_t collectData(void *ptr, size_t size, size_t nmemb, void *stream)
{
//  char *debug;
//  debug = (char*)malloc(size*nmemb + 1);
//  strncpy(debug, ptr, nmemb*size);
//  debug[nmemb*size]='\0';
//  syslog(LOG_NOTICE, debug);
  char *streamPtr=NULL;
  if(stream)
  {
//    syslog(LOG_NOTICE, "stream is not null");
    streamPtr = *((char**)stream);
  }
  
  if(!streamPtr)
  {
//    syslog(LOG_NOTICE, "streamPtr is null");
    streamPtr = (char *)malloc(nmemb*size+1*sizeof(char));
    streamPtr[0]='\0';
  }
  else
  {
//    syslog(LOG_NOTICE, "streamPtr is not null");
    char *tempBuf;
    tempBuf = (char *)malloc((strlen(streamPtr)+1)*sizeof(char));
    tempBuf[0]='\0';
    strcpy(tempBuf, streamPtr);
//    syslog(LOG_NOTICE, tempBuf);
    free(streamPtr);
    streamPtr = (char *)malloc((strlen(tempBuf)+1)*sizeof(char)  + nmemb*size);
    streamPtr[0]='\0';
    strcpy(streamPtr, tempBuf);
    free(tempBuf);
  }

//  syslog(LOG_NOTICE, "streamPtr was:");
//  syslog(LOG_NOTICE, streamPtr);
//  syslog(LOG_NOTICE, "about to append:");
//  syslog(LOG_NOTICE, debug);
  strncat(streamPtr, ptr, nmemb*size);
//  syslog(LOG_NOTICE, "streamPtr is:");
//  syslog(LOG_NOTICE, streamPtr);

  *((char**)stream) = streamPtr;
  
  return nmemb*size;
}