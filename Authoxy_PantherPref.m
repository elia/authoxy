//
//  Authoxy_PantherPref.m
//  Authoxy-Panther
//
//  Created by Heath Raftery on Sun Dec 28 2003.
//  Copyright (c) 2003, 2004 HRSoftWorks. All rights reserved.
//
//  This file is part of Authoxy.
//
//  Authoxy is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  Authoxy is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Authoxy; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#import "Authoxy_PantherPref.h"

#include <unistd.h>
#include <syslog.h>

@implementation Authoxy_PantherPref

/**************************************************************/
/* initWithBundle                                             */
/* initialisation procedures. Set up the preference defaults  */
/**************************************************************/
- (id)initWithBundle:(NSBundle *)bundle
{
  if ( ( self = [super initWithBundle:bundle] ) != nil )
  {
    CFPropertyListRef value;

    appID = CFSTR("net.hrsoftworks.AuthoxyPref");

    lastSysModDate = [[NSDate alloc] initWithTimeIntervalSinceReferenceDate:(NSTimeInterval)0];
    lastPIDModDate = [[NSDate alloc] initWithTimeIntervalSinceReferenceDate:(NSTimeInterval)0];
    lastPortModDate =[[NSDate alloc] initWithTimeIntervalSinceReferenceDate:(NSTimeInterval)0]; 

    value = CFPreferencesCopyAppValue(CFSTR(AP_Authorization), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_Authorization), @"Undefined", appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_Address), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_Address), @"proxy.myhost.edu.au", appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_RemotePort), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_RemotePort), @"8080", appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_LocalPort), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_LocalPort), @"8080", appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_Logging), appID);
    if (!(value && CFGetTypeID(value) == CFBooleanGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_Logging), kCFBooleanFalse, appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_PromptCredentials), appID);
    if (!(value && CFGetTypeID(value) == CFBooleanGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_PromptCredentials), kCFBooleanFalse, appID);
    
//    value = CFPreferencesCopyAppValue(CFSTR(AP_AutoStart), appID);
//    if (!(value && CFGetTypeID(value) == CFBooleanGetTypeID()))
//    CFPreferencesSetAppValue(CFSTR(AP_AutoStart), kCFBooleanFalse, appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_DaemonPID), appID);
    if (!(value && CFGetTypeID(value) == CFNumberGetTypeID()))
    {
      int minusOne = -1;
      CFPreferencesSetAppValue(CFSTR(AP_DaemonPID),
                               CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &minusOne),
                               appID);
    }

    value = CFPreferencesCopyAppValue(CFSTR(AP_AutoConfig), appID);
    if (!(value && CFGetTypeID(value) == CFBooleanGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_AutoConfig), kCFBooleanFalse, appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_PACAddress), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_PACAddress), @"http://www.myhost.edu.au/proxy.pac", appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_ExternalConnections), appID);
    if (!(value && CFGetTypeID(value) == CFBooleanGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_ExternalConnections), kCFBooleanFalse, appID);
    
    //NTLM settings
    value = CFPreferencesCopyAppValue(CFSTR(AP_NTLM), appID);
    if (!(value && CFGetTypeID(value) == CFBooleanGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_NTLM), kCFBooleanFalse, appID);
    
    value = CFPreferencesCopyAppValue(CFSTR(AP_NTLM_Domain), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_NTLM_Domain), @"domain", appID);

    value = CFPreferencesCopyAppValue(CFSTR(AP_NTLM_Host), appID);
    if (!(value && CFGetTypeID(value) == CFStringGetTypeID()))
      CFPreferencesSetAppValue(CFSTR(AP_NTLM_Host), @"host", appID);

    lastLocalPort = [[NSMutableString alloc] initWithCapacity:32];
    [lastLocalPort setString:@"unknown"];
    
    bRunning = FALSE; //since the button is "Start Authoxy" by default
    
    [fChanges setStringValue:@""];
    //Setup the authorization view
//    [aAuthorization setString:"net.hrsoftworks.AuthoxyPref.authorized"];
//    [aAuthorization setDelegate:self];
//    [aAuthorization updateStatus:self];
  }
  return self;
}

/**************************************************************/
/* dealloc                                                    */
/* free the stuff we've alloc'ed                              */
/*                                                            */
/**************************************************************/
- (void)dealloc
{
  [lastSysModDate release];
  [lastPIDModDate release];
  [lastPortModDate release];
  
  [lastLocalPort release];
  
  [super dealloc];
}

/**************************************************************/
/* authorizationViewDidDeauthorize                            */
/* Lock was successfully unlocked. Make the settings available*/
/**************************************************************/
//- (void)authorizationViewDidDeauthorize:(SFAuthorizationView *)view
//{
//  [[fTabs tabViewItemAtIndex:0] setEnabled:YES];
//  [[fTabs tabViewItemAtIndex:1] setEnabled:YES];
//  [fTabs selectTabViewItemAtIndex:0];
//}

/**************************************************************/
/* authorizationViewDidAuthorize                              */
/* Lock is locked. Lock off the settings.                     */
/**************************************************************/
//- (void)authorizationViewDidAuthorize:(SFAuthorizationView *)view
//{
//  [[fTabs tabViewItemAtIndex:0] setEnabled:NO];
//  [[fTabs tabViewItemAtIndex:1] setEnabled:NO];
//  [fTabs selectTabViewItemAtIndex:2];
//}

/**************************************************************/
/* mainViewDidLoad                                            */
/* fill the boxes with the appropriate values as the view     */
/* comes up                                                   */
/**************************************************************/
- (void)mainViewDidLoad
{
  char *un=NULL, *pw=NULL;

  CFPreferencesAppSynchronize(appID);
  
  if(decodePassKey((char *)[(NSString*)CFPreferencesCopyAppValue( CFSTR(AP_Authorization), appID ) cString], &un, &pw))
  {
    //decode was unsuccessful, so fill in default values
    [fUsername setStringValue:@"noone"];
    [fPassword setStringValue:@"nowhere"];
  }
  else
  {
    [fUsername setStringValue:[NSString stringWithCString:un]];
    [fPassword setStringValue:[NSString stringWithCString:pw]];
  }

  free(un);
  free(pw);
  
  [fAddress setStringValue:(NSString*)CFPreferencesCopyAppValue(CFSTR(AP_Address), appID)];
  [fRemotePort setStringValue:(NSString*)CFPreferencesCopyAppValue(CFSTR(AP_RemotePort), appID)];
  [fLocalPort setStringValue:(NSString*)CFPreferencesCopyAppValue(CFSTR(AP_LocalPort), appID)];
  [cLogging setState:CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_Logging), appID))];
  [cExternalConnections setState:CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_ExternalConnections), appID))];
  [cPromptForCredentials setState:CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_PromptCredentials), appID))];
  CFNumberGetValue(CFPreferencesCopyAppValue(CFSTR(AP_DaemonPID), appID),
                   kCFNumberSInt32Type,
                   &daemonPID);
  [fPACAddress setStringValue:(NSString*)CFPreferencesCopyAppValue(CFSTR(AP_PACAddress), appID)];
  if(CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_AutoConfig), appID)))
    [rAutoConfig performClick:self];
  else
    [rNoAutoConfig performClick:self];
     
  [self setAutoManualConfig:mAutoManualConfig];

  //NTLM
  [fNTLMDomain setStringValue:(NSString*)CFPreferencesCopyAppValue(CFSTR(AP_NTLM_Domain), appID)];
  [fNTLMHost setStringValue:(NSString*)CFPreferencesCopyAppValue(CFSTR(AP_NTLM_Host), appID)];
  [cNTLMEnabled setState:CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_NTLM), appID))];
  [self setNTLMConfig:cNTLMEnabled];
  
  //that's it, just set this updateStatus method going every second
  if (statusTimer != nil)
    [statusTimer invalidate];
  statusTimer = [NSTimer scheduledTimerWithTimeInterval:(NSTimeInterval)1
                                                 target:self
                                               selector:@selector(updateStatus:)
                                               userInfo:nil
                                                repeats:YES];
}

/**************************************************************/
/* willSelect                                                 */
/* Pane has been reselected. Start the status update timer    */
/**************************************************************/
- (void)willSelect;
{
  //the pane has appeared, so start this status update timer again
  if([statusTimer respondsToSelector:@selector(setFireDate:)])
    if([statusTimer isValid])
      [statusTimer setFireDate:[NSDate dateWithTimeIntervalSinceNow:1]];
}

/**************************************************************/
/* updateStatus                                               */
/* called periodically to set the status string and           */
/* start/stop button                                          */
/**************************************************************/
- (void)updateStatus:(NSTimer*)theTimer
{
  NSMutableString *statusString = [NSMutableString stringWithCapacity:60];

  NSFileManager *myManager = [NSFileManager defaultManager];
  NSDictionary *authoxydPort = [myManager fileAttributesAtPath:AUTHOXYD_PORT_PATH traverseLink:YES];
  if(authoxydPort)
  {
    NSDate *PortModDate = [authoxydPort objectForKey:NSFileModificationDate];
    if([PortModDate compare:lastPortModDate] == NSOrderedDescending)
    {
      [lastLocalPort setString:[NSString stringWithContentsOfFile:AUTHOXYD_PORT_PATH]];
      
      [lastPortModDate release];
      lastPortModDate = [PortModDate retain];
    }
  }
  
  NSDictionary *authoxydPID = [myManager fileAttributesAtPath:AUTHOXYD_PID_PATH traverseLink:YES];
  if(authoxydPID)
  {
    NSDate *PIDModDate = [authoxydPID objectForKey:NSFileModificationDate];
    if([PIDModDate compare:lastPIDModDate] == NSOrderedDescending)
    {
      NSString *PIDStr = [NSString stringWithContentsOfFile:AUTHOXYD_PID_PATH];
      daemonPID = [PIDStr intValue];
      
      [lastPIDModDate release];
      lastPIDModDate = [PIDModDate retain];
    }
  }
  else
    daemonPID = -1;
  
  if(daemonPID != -1)
  {
    int count;
    int err;
    int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PGRP, daemonPID};
    size_t length=0;
    kinfo_proc *result;
    //Call sysctl with a NULL buffer to find out how big the result would be
    //if we were to call it with a kinfo_proc buffer.
    //The number of process in the group is then the length divided by the sizeof a single kinfo_proc!
    err = sysctl(name, (sizeof(name) / sizeof(*name)), NULL, &length, NULL, 0);
    //Ha! Gay... we have to call sysctl twice, otherwise the length returned is wrong!
    result = malloc(length);
    err = sysctl(name, (sizeof(name) / sizeof(*name)), result, &length, NULL, 0);
    if((err != -1) && (count = length / sizeof(kinfo_proc)))
    {
      if(count > 1)
        [statusString setString:
          [NSString stringWithFormat:@"%d daemons running\non 127.0.0.1 port %@", count, lastLocalPort]];
      else
        [statusString setString:
          [NSString stringWithFormat:@"%d daemon running\non 127.0.0.1 port %@", count, lastLocalPort]];
      bRunning=TRUE;
    }
    else
    {
      //if we get here, then the PID in the file does not match any running daemons. In other words we are out of
      //sync with the daemon. This may happen if the .pid file disappears while the daemon is running. In an attempt
      //to regain contact, we'll try force quitting the daemon. Not sure if killall always exists though!
      system("killall authoxyd"); //dangerous really. I don't think there will be other authoxyd's around, but
                                  //there may not be a killall program
      
      [statusString setString:NOT_RUNNING_STRING];
      bRunning=FALSE;
//      daemonPID=-1;
    }
  }
  else
  {
    [statusString setString:NOT_RUNNING_INSTRUCTIONS_STRING];
    bRunning=FALSE;
  }
  [bStartStop setTitle:(bRunning ? STOP_BUTTON_TITLE : START_BUTTON_TITLE)];
  [bTestConnection setEnabled:!bRunning];
  [fStatus setStringValue:statusString];

  if([[[tTabs selectedTabViewItem] identifier] isEqualToString:@"tvMessages"])
  {
    //check to see if we should update the messages
    NSDictionary *systemLog = [myManager fileAttributesAtPath:SYSTEM_LOG_PATH traverseLink:YES];
    if(systemLog)
    {
      NSDate *sysModDate = [systemLog objectForKey:NSFileModificationDate];
      if([sysModDate compare:lastSysModDate] == NSOrderedDescending)
      {
        NSNumber *sysModSize = [systemLog objectForKey:NSFileSize];
        if(sysModSize && ([sysModSize intValue] > MAX_LOG_SIZE))
        {
          [tMessages setString:@"The system log has grown too large to parse reliably."];
        }
        else
        {
          NSString *logStr = [NSString stringWithContentsOfFile:SYSTEM_LOG_PATH];
          NSMutableString *authLogStr = [NSMutableString string];
          NSRange myRange = {0,1};
          NSRange mySearchRange;
          unsigned int endIndex, length = [logStr length];
          while(myRange.location < length)
          {
            [logStr getLineStart:&myRange.location end:&endIndex contentsEnd:nil forRange:myRange];
            myRange.length=endIndex-myRange.location;
            mySearchRange = [logStr rangeOfString:@"authoxyd: " options:0 range:myRange];
            if(mySearchRange.length != 0)
            {
              myRange.length = 16; //size of time stamp
              [authLogStr appendString:[logStr substringWithRange:myRange]];
              mySearchRange.location += 8;  //skip the search word
              mySearchRange.length = endIndex-mySearchRange.location;
              [authLogStr appendString:[logStr substringWithRange:mySearchRange]];
            }
            myRange.location = endIndex;
            myRange.length = 1;
          }
          
          [tMessages setString:authLogStr];
          
          myRange.location = [authLogStr length];
          [tMessages scrollRangeToVisible:myRange];
        }
        
        [lastSysModDate release];
        lastSysModDate = [sysModDate retain];
      }
    }
  }
}

/**************************************************************/
/* didUnselect                                                */
/* PreferencePane has been closed, set settings and clean up  */
/**************************************************************/
- (void)didUnselect
{
  [self setSettings];
  
//and stop the status timer
  if([statusTimer respondsToSelector:@selector(setFireDate:)])
    [statusTimer setFireDate:[NSDate distantFuture]];
}

/**************************************************************/
/* startStop                                                  */
/* button has been clicked. Start or stop daemon as appro     */
/**************************************************************/
- (IBAction)startStop:(id)sender
{
  if(!bRunning)
  {
    /* make sure settings are up to date */
    [self setSettings];
    [fChanges setStringValue:@""]; //hide the restart msg

    NSString *daemonPath = [[NSBundle bundleWithIdentifier:@"net.hrsoftworks.AuthoxyPref"] pathForAuxiliaryExecutable:@"authoxyd"];
    if(daemonPath != NULL)
    {
      NSTask *daemon = [NSTask launchedTaskWithLaunchPath:daemonPath arguments:[self getDaemonStartArgs]];
      
//      [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:10]];  //pause for two seconds before getting the PID
      
    //Note that this is just an educated guess at best. Because daemon() calls fork(), the PID could be
    //anything. This only way to ensure we have the correct PID is to get the daemon to report it after
    //becoming a daemon, and that is just what happens. The PID file is overwritten by the daemon when it starts
    //and we retrieve the value from there during updateStatus.
      daemonPID = [daemon processIdentifier] + 1; //plus one because it daemon and increments the PID
                                                  //(hope it doesn't loop or skip or something)
                                                  //WTF? As of 040112, it seems to be PID+2??? Today it's not. Watch this fix_prebinding!
                                                  //      if([statusTimer respondsToSelector:@selector(setFireDate:)])
                                                  //        [statusTimer setFireDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];
    }
    else
    {
      if([statusTimer respondsToSelector:@selector(setFireDate:)])
        [statusTimer setFireDate:[NSDate distantFuture]];
      [fStatus setStringValue:@"Fatal Error: Daemon not found.\nReinstall Authoxy"];
    }      
  }
  else
  {
//    NSString *kill = [NSString stringWithFormat:@"kill %d", daemonPID];
    system("killall -CONT authoxyd"); //wake the silly buggers up
    system("killall authoxyd");       //and then kill them!!
    
    NSFileManager *man = [NSFileManager defaultManager];
    [man removeFileAtPath:AUTHOXYD_PID_PATH handler:nil];
    [man removeFileAtPath:AUTHOXYD_PORT_PATH handler:nil];
  }
}

/**************************************************************/
/* testConnection                                             */
/* Trial a connection attempt logging the connection traffic. */
/**************************************************************/
- (IBAction)testConnection:(id)sender
{
  if(bRunning) //you never know, the button might not have been disabled
    return;
  
  [self setSettings];
  [fChanges setStringValue:@""]; //hide the restart msg

  NSString *daemonPath = [[NSBundle bundleWithIdentifier:@"net.hrsoftworks.AuthoxyPref"] pathForAuxiliaryExecutable:@"authoxyd"];
  if(daemonPath != NULL)
  {
    NSArray *args = [self getDaemonStartArgs];
    NSMutableArray *modifiedArgs = [NSMutableArray arrayWithArray:args];
    [modifiedArgs replaceObjectAtIndex:daLogging withObject:ARGUMENT_TESTING];
    [NSTask launchedTaskWithLaunchPath:daemonPath arguments:modifiedArgs];
  }
  else
    [fStatus setStringValue:@"Fatal Error: Daemon not found.\nReinstall Authoxy"];
}

/**************************************************************/
/* setAutoManualConfig                                        */
/* Either manual proxy setting or automatic config has been   */
/* selected. Make the necessary changes to the GUI            */
/**************************************************************/
- (IBAction)setAutoManualConfig:(id)sender
{
  [self changeMade:sender];

//  if([rAutoConfig state] == NSOnState)
  if([[sender selectedCell] tag] == AUTO_CELL_TAG)
  {
    [fPACAddress setEnabled:YES];
    [fRemotePort setEnabled:NO];
    [fAddress setEnabled:NO];
  }
  else
  {
    [fPACAddress setEnabled:NO];
    [fRemotePort setEnabled:YES];
    [fAddress setEnabled:YES];
  }
}

/**************************************************************/
/* setNTLMConfig                                              */
/* NTLM support has been toggled. Make the necessary changes  */
/* to the GUI                                                 */
/**************************************************************/
- (IBAction)setNTLMConfig:(id)sender
{
  [self changeMade:sender];
  
  if([sender state] == NSOnState)
  {
    [fNTLMDomain setEnabled:YES];
    [fNTLMHost setEnabled:YES];
  }
  else
  {
    [fNTLMDomain setEnabled:NO];
    [fNTLMHost setEnabled:NO];
  }
}

/**************************************************************/
/* changeMade                                                 */
/* Looks like a change was made to the settings. Show the msg */
/**************************************************************/
- (IBAction)changeMade:(id)sender
{
  if(bRunning)
    [fChanges setStringValue:CHANGES_STRING];
}

/**************************************************************/
/* setSettings                                                */
/* Settings should be written to disk everytime a change is   */
/* made                                                       */
/**************************************************************/
- (void)setSettings
{
  char *encoded;

  encoded = encodePassKey( (char*)[[fUsername stringValue] cString], (char*)[[fPassword stringValue] cString]);

  CFPreferencesSetAppValue(CFSTR(AP_Authorization), [NSString stringWithCString:encoded], appID);
  CFPreferencesSetAppValue(CFSTR(AP_Address), [fAddress stringValue], appID);
  CFPreferencesSetAppValue(CFSTR(AP_RemotePort), [fRemotePort stringValue], appID);
  CFPreferencesSetAppValue(CFSTR(AP_LocalPort), [fLocalPort stringValue], appID);
  if([cLogging state] == NSOnState)
    CFPreferencesSetAppValue(CFSTR(AP_Logging), kCFBooleanTrue, appID);
  else
    CFPreferencesSetAppValue(CFSTR(AP_Logging), kCFBooleanFalse, appID);
  if([cExternalConnections state] == NSOnState)
    CFPreferencesSetAppValue(CFSTR(AP_ExternalConnections), kCFBooleanTrue, appID);
  else
    CFPreferencesSetAppValue(CFSTR(AP_ExternalConnections), kCFBooleanFalse, appID);
  if([cPromptForCredentials state] == NSOnState)
    CFPreferencesSetAppValue(CFSTR(AP_PromptCredentials), kCFBooleanTrue, appID);
  else
    CFPreferencesSetAppValue(CFSTR(AP_PromptCredentials), kCFBooleanFalse, appID);
  
  CFPreferencesSetAppValue(CFSTR(AP_DaemonPID),
                           CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &daemonPID),
                           appID);
  CFPreferencesSetAppValue(CFSTR(AP_PACAddress), [fPACAddress stringValue], appID);
  if([rAutoConfig state] == NSOnState)
    CFPreferencesSetAppValue(CFSTR(AP_AutoConfig), kCFBooleanTrue, appID);
  else
    CFPreferencesSetAppValue(CFSTR(AP_AutoConfig), kCFBooleanFalse, appID);

  //NTLM
  CFPreferencesSetAppValue(CFSTR(AP_NTLM_Domain), [fNTLMDomain stringValue], appID);
  CFPreferencesSetAppValue(CFSTR(AP_NTLM_Host), [fNTLMHost stringValue], appID);
  if([cNTLMEnabled state] == NSOnState)
    CFPreferencesSetAppValue(CFSTR(AP_NTLM), kCFBooleanTrue, appID);
  else
    CFPreferencesSetAppValue(CFSTR(AP_NTLM), kCFBooleanFalse, appID);
  
  CFPreferencesAppSynchronize(appID);
  
  free(encoded);
}

/**************************************************************/
/* getDaemonStartArgs                                         */
/* return an array of the arguments for the daemon            */
/**************************************************************/
- (NSArray *)getDaemonStartArgs
{
  /* get the commandline arguments for the daemon from the current settings */
  NSArray *args;

  CFPreferencesAppSynchronize(appID);
  
  if(CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_AutoConfig), appID)))
  {
    args = [NSArray arrayWithObjects:
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_Authorization), appID),
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_PACAddress), appID),	//note using PACaddress in place of address
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_RemotePort), appID),
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_LocalPort), appID),
      [NSString stringWithString:
        (CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_Logging), appID)) ? ARGUMENT_LOGGING : ARGUMENT_NO_LOGGING)],
      @"true",	//use auto config
      [NSString stringWithString:
        (CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_ExternalConnections), appID)) ? @"true" : @"false")],
      nil];
  }
  else
  {
    args = [NSArray arrayWithObjects:
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_Authorization), appID),
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_Address), appID),
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_RemotePort), appID),
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_LocalPort), appID),
      [NSString stringWithString:
        (CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_Logging), appID)) ? ARGUMENT_LOGGING : ARGUMENT_NO_LOGGING)],
      @"false",	//no auto config here
      [NSString stringWithString:
        (CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_ExternalConnections), appID)) ? @"true" : @"false")],
      nil];
  }
  
  if(CFBooleanGetValue(CFPreferencesCopyAppValue(CFSTR(AP_NTLM), appID)))
  {
    NSArray *argsNTLM = [args arrayByAddingObjectsFromArray:[NSArray arrayWithObjects:
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_NTLM_Domain), appID), //add Domain and Host settings if using NTLM
      (NSString*)CFPreferencesCopyAppValue(CFSTR(AP_NTLM_Host), appID),
      nil]];
    
    return argsNTLM;
  }
  else
    return args;
}

/****************************************************************/
/* didSelectTabViewItem                                         */
/* looks like the user selected a different tab. Should be act? */
/****************************************************************/
-(void)tabView:(NSTabView *)tabView didSelectTabViewItem:(NSTabViewItem *)tabViewItem
{
  if([[tabViewItem identifier] isEqualToString:@"tvMessages"])
  {
    //don't do anything for now
  }
}

@end