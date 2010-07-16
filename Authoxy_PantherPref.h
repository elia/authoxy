//
//  Authoxy_PantherPref.h
//  Authoxy-Panther
//
//  Created by Heath Raftery on Sun Dec 28 2003.
//  Copyright (c) 2003, 2004 HRSoftWorks. All rights reserved.
//
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
//  
//

#import <PreferencePanes/PreferencePanes.h>
#import <Cocoa/Cocoa.h>
//#import <SecurityInterface/SFAuthorizationView.h>

#import <sys/types.h>
#import <sys/sysctl.h>

typedef struct kinfo_proc kinfo_proc;

#import "defaults.h"
#import "base64.h"

#define AUTO_CELL_TAG 1

#define AUTHOXYD_PID_PATH @"/tmp/authoxyd.pid"
#define AUTHOXYD_PORT_PATH @"/tmp/authoxyd.port"
#define SYSTEM_LOG_PATH   @"/var/log/system.log"

//ha, that's funny, 10.2 doesn't have setHidden, so I'm going to delete and add the text instead!
#define CHANGES_STRING    @"Changes will not take affect until Authoxy is stopped and restarted."
#define MAX_LOG_SIZE      750000

#define ARGUMENT_NO_LOGGING @"0"
#define ARGUMENT_LOGGING    @"1"
#define ARGUMENT_TESTING    @"2"

enum eDaemonArguments
{
  daAuthorization,
  daAddress,
  daRemotePort,
  daLocalPort,
  daLogging,
  daAutoConfiguration,
  daExternConnections,
  daNTLMDomain,
  daNTLMHost
};

#define STOP_BUTTON_TITLE               @"Stop Authoxy"
#define START_BUTTON_TITLE              @"Start Authoxy"

#define NOT_RUNNING_STRING              @"Not running"
#define NOT_RUNNING_INSTRUCTIONS_STRING @"Fill your settings in and then press \"Start Authoxy\"."

@interface Authoxy_PantherPref : NSPreferencePane 
{
//  IBOutlet SFAuthorizationView *aAuthorization;
  IBOutlet NSTabView *tTabs;
  
  IBOutlet NSTextField*   fAddress;
  IBOutlet NSTextField*   fPACAddress;
  IBOutlet NSTextField*   fPassword;
  IBOutlet NSTextField*   fRemotePort;
  IBOutlet NSTextField*   fLocalPort;
  IBOutlet NSTextField*   fUsername;
  IBOutlet NSTextField*   fStatus;
  IBOutlet NSTextField*   fChanges;
  IBOutlet NSButton*      bStartStop;
  IBOutlet NSButton*      bTestConnection;
  IBOutlet NSButton*      cLogging;
  IBOutlet NSButton*      cPromptForCredentials;
  IBOutlet NSButtonCell*  rAutoConfig;
  IBOutlet NSButtonCell*  rNoAutoConfig;
  IBOutlet NSMatrix*      mAutoManualConfig;
  IBOutlet NSButton*      cExternalConnections;
  
  //NTLM
  IBOutlet NSButton*      cNTLMEnabled;
  IBOutlet NSTextField*   fNTLMDomain;
  IBOutlet NSTextField*   fNTLMHost;
  
  IBOutlet NSTextView*    tMessages;
  
  CFStringRef appID;
  int daemonPID;
  int daemonPort;
  
  NSTimer *statusTimer;
  
  NSMutableString *lastLocalPort;
  NSDate *lastSysModDate;
  NSDate *lastPIDModDate;
  NSDate *lastPortModDate;
  
  bool bRunning;
}

- (IBAction)startStop:(id)sender;
- (IBAction)testConnection:(id)sender;
- (IBAction)setAutoManualConfig:(id)sender;
- (IBAction)setNTLMConfig:(id)sender;
- (IBAction)changeMade:(id)sender;

- (id)initWithBundle:(NSBundle *)bundle;
- (void)dealloc;
/*
- (void)authorizationViewDidDeauthorize:(SFAuthorizationView *)view;
- (void)authorizationViewDidAuthorize:(SFAuthorizationView *)view;
*/
- (void)mainViewDidLoad;
- (void)updateStatus:(NSTimer*)theTimer;
- (void)didUnselect;

- (void)setSettings;

- (NSArray *)getDaemonStartArgs;

@end