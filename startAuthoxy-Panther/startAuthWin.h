/* startAuthWin */

#import <Cocoa/Cocoa.h>

#include "base64.h"

#define AUTHOXYD_PID_PATH @"/tmp/authoxyd.pid"

@interface startAuthWin : NSWindow
{
  IBOutlet NSTextField *status;
  IBOutlet NSPanel *credentialsPanel;

  IBOutlet NSTextField *fUsername;
  IBOutlet NSTextField *fPassword;
  
  CFStringRef appID;
}

- (IBAction)panelButtons:(id)sender;

- (void)awakeFromNib;
- (void)doTheStuff:(NSTimer*)theTimer;
- (void)exitTimer:(NSTimer*)theTimer;
- (NSString*)getDaemonStartStr;
- (NSArray *)getDaemonStartArgs;

#define AP_Authorization      "AuthoxyAuthorization"
#define AP_Address            "AuthoxyAddress"
#define AP_RemotePort         "AuthoxyRemotePort"
#define AP_LocalPort          "AuthoxyLocalPort"
#define AP_Logging            "AuthoxyLogging"
#define AP_AutoStart          "AuthoxyAutoStart"
#define AP_DaemonPID          "AuthoxyDaemonPID"
#define AP_AutoConfig         "AuthoxyAutoConfig"
#define AP_PACAddress         "AuthoxyPACAddress"
#define AP_PromptCredentials  "AuthoxyPromptCredentials"
#define AP_ExternalConnections "AuthoxyExternalConnections"

#define AP_NTLM               "AuthoxyUsingNTLM"
#define AP_NTLM_Domain        "AuthoxyNTLMDomain"
#define AP_NTLM_Host          "AuthoxyNTLMHost"

#define BUTTON_OK     1
#define BUTTON_CANCEL 2

#define ARGUMENT_NO_LOGGING @"0"
#define ARGUMENT_LOGGING    @"1"
#define ARGUMENT_TESTING    @"2"

@end