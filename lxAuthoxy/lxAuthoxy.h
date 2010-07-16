#import <Cocoa/Cocoa.h>
#import <LXFramework/LXOption.h>

@interface Authoxy : LXOption
{
}

- (NSString *)descriptionWithCurrentSettings: (id)locationSettingsForPlugin forLocationNamed: (NSString *)locationName;
- (BOOL)usesDefaultAction;
- (BOOL)hasCustomChangePanel;
//- (NSString *)name;
- (NSString *)keyName;
- (NSArray *)pathsToPrefs;
- (void)prepareForChange;
- (void)concludeChange;
- (NSString *)pathToLaunch;
- (void)makeActiveWithLocationNamed:(NSString *)locationName withSetting:(id)setting;
@end

#define AUTHOXY_PREF_PATH @"~/Library/Preferences/net.hrsoftworks.AuthoxyPref.plist"
#define AUTHOXY_PREF_PATH_COPY @"~/Library/Preferences/net.hrsoftworks.AuthoxyPref.plist.lxTemp"
#define FULL_AUTHOXY_PREF_PATH [[NSString stringWithString:AUTHOXY_PREF_PATH] stringByExpandingTildeInPath]
#define FULL_AUTHOXY_PREF_PATH_COPY [[NSString stringWithString:AUTHOXY_PREF_PATH_COPY] stringByExpandingTildeInPath]