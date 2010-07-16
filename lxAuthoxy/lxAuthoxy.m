#import "lxAuthoxy.h"
#import <LXFrameWork/LXHelperFunctions.h>

@implementation Authoxy

/**************************************************************/
/* descriptionWithCurrentSettings:forLocationNamed:						*/
/**************************************************************/
- (NSString *)descriptionWithCurrentSettings: (id)locationSettingsForPlugin forLocationNamed: (NSString *)locationName
{
  return [NSString stringWithFormat:@"You may choose settings for Authoxy, which will be used for the location \"%@\".", locationName];
}

/**************************************************************/
/* usesDefaultAction																					*/
/**************************************************************/
- (BOOL)usesDefaultAction
{
  return NO;
}

/**************************************************************/
/* hasCustomChangePanel																				*/
/**************************************************************/
- (BOOL)hasCustomChangePanel
{
  return NO;
}

/**************************************************************/
/* keyName																										*/
/**************************************************************/
- (NSString *)keyName
{
  return @"lxAuthoxy";
}

/**************************************************************/
/* pathsToPrefs																								*/
/**************************************************************/
- (NSArray *)pathsToPrefs
{
  return [NSArray arrayWithObject:AUTHOXY_PREF_PATH];
}

/**************************************************************/
/* prepareForChange																						*/
/**************************************************************/
- (void)prepareForChange
{
  NSFileManager *myFM = [NSFileManager defaultManager];
  [myFM removeFileAtPath:FULL_AUTHOXY_PREF_PATH_COPY handler:nil];
  if(![myFM copyPath:FULL_AUTHOXY_PREF_PATH toPath:FULL_AUTHOXY_PREF_PATH_COPY handler:nil])
    LXLogError(@"an error occured when trying to backup the preferences file. Things may not work so well.", self);
}

/**************************************************************/
/* concludeChange																							*/
/**************************************************************/
- (void)concludeChange
{
  NSFileManager *myFM = [NSFileManager defaultManager];
  [myFM removeFileAtPath:FULL_AUTHOXY_PREF_PATH handler:nil];
  if(![myFM copyPath:FULL_AUTHOXY_PREF_PATH_COPY toPath:FULL_AUTHOXY_PREF_PATH handler:nil])
    LXLogError(@"an error occured when restore the preferences backup file. Things may not work so well.", self);
  [myFM removeFileAtPath:FULL_AUTHOXY_PREF_PATH_COPY handler:nil];
}

/**************************************************************/
/* pathToLaunch																								*/
/**************************************************************/
- (NSString *)pathToLaunch
{
  NSArray *locations = NSSearchPathForDirectoriesInDomains(NSAllLibrariesDirectory, NSAllDomainsMask, YES);
  NSString *prefPath = [NSString string];
  NSFileManager *myFiler = [NSFileManager defaultManager];
  
  int i;

  /* search all the Library directories for the prefPane */
  for(i=0; i<[locations count]; i++)
  {
    prefPath = [NSString stringWithFormat:@"%@/PreferencePanes/Authoxy.prefPane", [locations objectAtIndex:i] ];
    if([myFiler fileExistsAtPath:prefPath])
      break;
  }

  if(i==[locations count])
  {
    LXLogError(@"we were unable to find the Authoxy preference pane. Are you sure you've installed Authoxy properly?", self);
    return nil;
  }
  else
    return prefPath;
}

/**************************************************************/
/* makeActiveWithLocationNamed:withSetting:										*/
/**************************************************************/
- (void)makeActiveWithLocationNamed:(NSString *)locationName withSetting:(id)setting
{
  if([setting writeToFile:FULL_AUTHOXY_PREF_PATH atomically:YES])
  {
    NSTask* startAuthoxy = [NSTask launchedTaskWithLaunchPath:@"/Applications/startAuthoxy.app/Contents/MacOS/startAuthoxy" arguments:[NSArray array]];
    if(![startAuthoxy isRunning])
      LXLogError(@"the startAuthoxy application was not found. Are you sure you've installed Authoxy properly?", self);
  }
  else
    LXLogError(@"the preference file could not be written. Please contact Authoxy's developer.", self);
}

/**************************************************************/
/* saveSettingIntoLocationNamed:															*/
/**************************************************************/
- (id)saveSettingsIntoLocationNamed: (NSString *)locationName
{
  return [NSString stringWithContentsOfFile:FULL_AUTHOXY_PREF_PATH];
}

/**************************************************************/
/* captureCurrentSystemSettingsIntoLocationNamed:							*/
/**************************************************************/
- (id)captureCurrentSystemSettingsIntoLocationNamed: (NSString *)locationName
{
  return [NSString stringWithContentsOfFile:FULL_AUTHOXY_PREF_PATH];
}

@end
