#import "startAuthWin.h"

@implementation startAuthWin

- (void)awakeFromNib
{
  NSTimer *theTimer;

  appID = CFSTR("net.hrsoftworks.AuthoxyPref");

  CFPropertyListRef check = NULL;
  check = CFPreferencesCopyAppValue(CFSTR(AP_PromptCredentials), appID);
  if(check && CFBooleanGetValue(check))  //then we need to prompt for the username and password, base64 it, and put it back in the prefs
    theTimer = [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(promptForCredentials:) userInfo:nil repeats:NO];
  else
    theTimer = [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(doTheStuff:) userInfo:nil repeats:NO];
}

- (void)promptForCredentials:(NSTimer*)theTimer
{
  [NSApp beginSheet:credentialsPanel modalForWindow:self modalDelegate:self didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:) contextInfo:theTimer];
}

- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo
{
  if(returnCode == NSRunStoppedResponse)
  {
    char *encoded = encodePassKey( (char*)[[fUsername stringValue] cString], (char*)[[fPassword stringValue] cString]);
    
    CFPreferencesSetAppValue(CFSTR(AP_Authorization), [NSString stringWithCString:encoded], appID);
    
    free(encoded);
  }
  
  [credentialsPanel orderOut:nil];  //force the sheet to disappear
  
  contextInfo = [NSTimer scheduledTimerWithTimeInterval:0.5 target:self selector:@selector(doTheStuff:) userInfo:nil repeats:NO];
}

- (IBAction)panelButtons:(id)sender
{
  if([sender tag] == BUTTON_OK)
    [NSApp endSheet:credentialsPanel returnCode:NSRunStoppedResponse];
  else
    [NSApp endSheet:credentialsPanel returnCode:NSRunAbortedResponse];
}

- (void)doTheStuff:(NSTimer*)theTimer
{
  NSString *daemonPath;

  system("killall authoxyd");

  daemonPath = [self getDaemonStartStr];
  if(daemonPath)
  {
    NSArray *args = [self getDaemonStartArgs];
    if(args)
    {
      NSTask *daemon = [NSTask launchedTaskWithLaunchPath:daemonPath arguments:args];
//      int daemonPID = [daemon processIdentifier] + 1;  //plus one because it daemons and increments the PID
                                                       //(hope it doesn't loop or skip or something)
      //okay, there's no guarantee that that +1 shit will give us the right PID. Instead, we're going to
      //leave it up to the daemon to report its own PID. Thus, we will give it a couple of seconds to
      //do that, and then retrieve the value from there.
      int daemonPID = -1;
      [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:2]];
      
      if([daemon isRunning])  //then it hasn't daemon'ed yet, give it another couple of secs
        [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:2]];
      
      NSDictionary *authoxydPID = [[NSFileManager defaultManager] fileAttributesAtPath:AUTHOXYD_PID_PATH
                                                                          traverseLink:YES];
      if(authoxydPID)
      {
        NSString *PIDStr = [NSString stringWithContentsOfFile:AUTHOXYD_PID_PATH];
        daemonPID = [PIDStr intValue];
        [status setStringValue:@"Successful!"];
      }
      else
        [status setStringValue:@"Daemon did not start!"];
  
      //save that daemonPID
      CFPreferencesSetAppValue(CFSTR("AuthoxyDaemonPID"),
                              CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &daemonPID),
                              appID);
    }
    else
      [status setStringValue:@"Failed: configure Authoxy in System Preferences first."];
  }
  else
    [status setStringValue:@"Failed: re-install Authoxy."];
  
  theTimer = [NSTimer scheduledTimerWithTimeInterval:2 target:self selector:@selector(exitTimer:) userInfo:nil repeats:NO];
}

- (void)exitTimer:(NSTimer*)theTimer
{
  [NSApp terminate:self];
}

- (NSString*)getDaemonStartStr
{
  NSArray *locations = NSSearchPathForDirectoriesInDomains(NSAllLibrariesDirectory, NSAllDomainsMask, YES);
  NSString *daemonPath = [NSString string];
  NSFileManager *myFiler = [NSFileManager defaultManager];
  int i;
  /* search all the Library directories for the daemon */
  for(i=0; i<[locations count]; i++)
  {
    daemonPath = [NSString stringWithFormat:@"%@/PreferencePanes/Authoxy.prefPane/Contents/MacOS/authoxyd", [locations objectAtIndex:i] ];
    if([myFiler fileExistsAtPath:daemonPath])
      break;
  }
  if(i==[locations count])	/* we didn't find it! */
    return NULL;
  else	/* we did find it, return it */
    return daemonPath;
}

/**************************************************************/
/* getDaemonStartArgs                                         */
/* return an array of the arguments for the daemon						*/
/**************************************************************/
- (NSArray *)getDaemonStartArgs
{
  CFPropertyListRef check = NULL;
  check = CFPreferencesCopyAppValue(CFSTR(AP_Authorization), appID);
  if(check)
  {
    [(NSString*) check release];
    /* get the commandline arguments for the daemon from the current settings */
    NSArray *args;
  
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
  else
    return NULL;
}

@end