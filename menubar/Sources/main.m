// Cove Menu Bar — macOS menu bar companion for Cove.
//
// Originally created by Robby McCullough (github.com/RobbyMcCullough/cove-menubar,
// MIT) and folded into the official Cove project with his blessing.
// Copyright (c) 2026 Robby McCullough. MIT License.
//
// This source is embedded into cove.sh at compile time (see compile.sh) and
// built on the user's machine by `cove menubar enable` — dependency-free,
// clang + system frameworks only. Keep it that way.
//
// Status is read via `cove status --porcelain` (key=value per line) — a
// stable contract defined in commands/status. The human-readable status
// output can change freely; the porcelain keys cannot.
//
// Menu architecture: the menu skeleton is built ONCE, with the three core
// service rows pre-seeded, and every refresh mutates item titles/images in
// place. Rebuilding items on refresh caused two visible glitches: the first
// render had no service rows (so no icon column — text flush left), and the
// first poll's rebuild re-layouted the open menu, making everything jump.

#import <Cocoa/Cocoa.h>
#import <CoreImage/CoreImage.h>
#import <ServiceManagement/ServiceManagement.h>
#import <UserNotifications/UserNotifications.h>

typedef void (^CoveCommandCompletion)(int status, NSString *output, NSError *error);

// Index of the first service row: summary + separator come before it.
static const NSInteger kServiceRowStartIndex = 2;

@interface AppDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>
@property(nonatomic, strong) NSStatusItem *statusItem;
@property(nonatomic, strong) NSMenu *menu;
@property(nonatomic, strong) NSTimer *refreshTimer;
@property(nonatomic, strong) NSTimer *updateCheckTimer;
// Ordered porcelain keys (caddy, mariadb, mailpit, php-fpm-<ver>...) and
// their running state from the most recent successful poll. serviceStates is
// tri-state via absence: no entry for a key yet = unknown ("…" row).
@property(nonatomic, strong) NSArray<NSString *> *serviceKeys;
@property(nonatomic, strong) NSDictionary<NSString *, NSNumber *> *serviceStates;
@property(nonatomic, assign) BOOL statesKnown;
@property(nonatomic, assign) BOOL busy;
// What the summary row says while busy ("Starting Cove…", "Creating x…").
@property(nonatomic, copy) NSString *busyText;
// Pulses the menu bar icon while a long action runs, so multi-second work
// (site creation, enable) reads as "working" instead of "locked up".
@property(nonatomic, strong) NSTimer *busyPulseTimer;
@property(nonatomic, assign) BOOL pulsePhase;
@property(nonatomic, copy) NSString *lastError;
// A failed user action (create/start/stop/login). Unlike lastError, this is
// NOT cleared by the next successful status poll — only by the next action —
// so the evidence doesn't vanish seconds after the failure.
@property(nonatomic, copy) NSString *lastActionError;
@property(nonatomic, copy) NSString *coveVersion;
@property(nonatomic, copy) NSString *latestVersion;
@property(nonatomic, assign) CFAbsoluteTime lastUserActionTime;
// Services seen newly stopped on the last poll, awaiting a second consecutive
// stopped poll before the "stopped unexpectedly" notification fires. Absorbs
// transient restarts (a terminal-run `cove enable`, service churn during
// `cove upgrade`) that a single-poll snapshot would misread as a crash.
@property(nonatomic, strong) NSMutableSet<NSString *> *pendingStopKeys;
@property(nonatomic, assign) BOOL notificationsAllowed;
@property(nonatomic, strong) NSImage *runningImage;
@property(nonatomic, strong) NSImage *partialImage;
@property(nonatomic, strong) NSImage *stoppedImage;
// Stable menu items, created once and mutated in place.
@property(nonatomic, strong) NSMenuItem *summaryItem;
@property(nonatomic, strong) NSMutableArray<NSMenuItem *> *serviceItems;
@property(nonatomic, strong) NSArray<NSString *> *serviceItemKeys;
@property(nonatomic, strong) NSMenuItem *errorItem;
@property(nonatomic, strong) NSMenuItem *actionItem;
@property(nonatomic, strong) NSMenuItem *refreshItem;
@property(nonatomic, strong) NSMenuItem *reloadItem;
@property(nonatomic, strong) NSMenuItem *sitesItem;
@property(nonatomic, strong) NSMenuItem *dashboardItem;
@property(nonatomic, strong) NSMenuItem *adminerItem;
@property(nonatomic, strong) NSMenuItem *mailpitItem;
@property(nonatomic, strong) NSMenuItem *launchItem;
@property(nonatomic, strong) NSMenuItem *versionItem;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    // NSStatusItem persists its visible flag in this app's defaults domain
    // (run.cove.menubar). A stale 0 there — e.g. left behind by the original
    // standalone build — would make every launch silently invisible, and
    // `cove menubar enable` replaces the bundle without touching preferences.
    // The item is never removal-allowed, so a hidden state can only be stale;
    // force it visible.
    self.statusItem.visible = YES;
    [self loadStatusImages];

    // Seed the core trio before the first poll so the very first render
    // already has the service rows (and their icon column). PHP-FPM rows for
    // pinned sites are appended when the first poll reports them.
    self.serviceKeys = @[ @"caddy", @"mariadb", @"mailpit" ];
    self.serviceStates = @{};
    self.serviceItems = [NSMutableArray array];
    self.serviceItemKeys = @[];

    [self buildMenuSkeleton];
    [self updateMenu];

    __weak typeof(self) weakSelf = self;
    [[UNUserNotificationCenter currentNotificationCenter]
        requestAuthorizationWithOptions:UNAuthorizationOptionAlert
                      completionHandler:^(BOOL granted, NSError *error) {
                          (void)error;
                          dispatch_async(dispatch_get_main_queue(), ^{
                              weakSelf.notificationsAllowed = granted;
                          });
                      }];

    [[[NSWorkspace sharedWorkspace] notificationCenter]
        addObserver:self
        selector:@selector(refreshStatus)
        name:NSWorkspaceDidWakeNotification
        object:nil];

    [self refreshStatus];

    // The menu refreshes on open (menuWillOpen:), so the timer only keeps the
    // *icon* honest. A generous interval + tolerance lets macOS coalesce the
    // wakeups instead of spinning up a bash pipeline every few seconds.
    self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:20.0
                                                        target:self
                                                      selector:@selector(refreshStatus)
                                                      userInfo:nil
                                                       repeats:YES];
    self.refreshTimer.tolerance = 5.0;

    [self checkForUpdates];
    self.updateCheckTimer = [NSTimer scheduledTimerWithTimeInterval:86400.0
                                                             target:self
                                                           selector:@selector(checkForUpdates)
                                                           userInfo:nil
                                                            repeats:YES];
    self.updateCheckTimer.tolerance = 3600.0;
}

- (void)menuWillOpen:(NSMenu *)menu {
    // Rebuild the Sites submenu before display (it isn't visible yet, so
    // this can't cause an on-screen re-layout), then poll for fresh state —
    // whose completion only mutates titles/images in place.
    [self rebuildSitesSubmenu];
    [self refreshStatus];
}

#pragma mark - Status polling

- (void)refreshStatus {
    if (self.busy) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:@[@"status", @"--porcelain"]
                       timeout:20.0
                    completion:^(int status, NSString *output, NSError *error) {
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        if (status == 0) {
            // Clear the prior error FIRST — applyPorcelainOutput may set a new
            // one (unparseable output), and it must survive this call.
            strongSelf.lastError = nil;
            [strongSelf applyPorcelainOutput:output];
        } else {
            strongSelf.lastError = error.localizedDescription ?: @"Unable to read Cove status.";
        }

        [strongSelf updateMenu];
    }];
}

- (void)applyPorcelainOutput:(NSString *)output {
    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSNumber *> *states = [NSMutableDictionary dictionary];

    for (NSString *rawLine in [output componentsSeparatedByCharactersInSet:
                               [NSCharacterSet newlineCharacterSet]]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        NSRange eq = [line rangeOfString:@"="];
        if (eq.location == NSNotFound || eq.location == 0) {
            continue;
        }
        NSString *key = [line substringToIndex:eq.location];
        NSString *value = [line substringFromIndex:eq.location + 1];

        if ([key isEqualToString:@"version"]) {
            self.coveVersion = value;
            continue;
        }
        if ([value isEqualToString:@"running"] || [value isEqualToString:@"stopped"]) {
            [keys addObject:key];
            states[key] = @([value isEqualToString:@"running"]);
        }
    }

    if (keys.count == 0) {
        // Porcelain output we can't read — treat as an error, not "all down".
        self.lastError = @"Unexpected status output from Cove.";
        return;
    }

    [self notifyUnexpectedStopsFrom:self.serviceStates to:states];

    self.serviceKeys = keys;
    self.serviceStates = states;
    self.statesKnown = YES;
}

// Post a notification for a service that died out from under a running stack.
// Suppressed when: states aren't established yet, the user just acted through
// the menu (start/stop churn), or EVERYTHING went down at once — that shape is
// almost always a deliberate `cove disable` from a terminal, not a crash.
// A stop must also survive TWO consecutive polls before it notifies: a service
// mid-restart (terminal-run `cove enable`, the multi-minute service churn of
// `cove upgrade`) is back up by the next poll and never alarms.
- (void)notifyUnexpectedStopsFrom:(NSDictionary<NSString *, NSNumber *> *)oldStates
                               to:(NSDictionary<NSString *, NSNumber *> *)newStates {
    if (!self.pendingStopKeys) {
        self.pendingStopKeys = [NSMutableSet set];
    }
    if (!self.statesKnown || !self.notificationsAllowed) {
        [self.pendingStopKeys removeAllObjects];
        return;
    }
    if (CFAbsoluteTimeGetCurrent() - self.lastUserActionTime < 20.0) {
        [self.pendingStopKeys removeAllObjects];
        return;
    }

    BOOL anyStillRunning = NO;
    for (NSNumber *running in newStates.allValues) {
        if (running.boolValue) {
            anyStillRunning = YES;
            break;
        }
    }
    if (!anyStillRunning) {
        [self.pendingStopKeys removeAllObjects];
        return;
    }

    NSMutableSet<NSString *> *stillPending = [NSMutableSet set];
    for (NSString *key in newStates) {
        if (newStates[key].boolValue) {
            continue;   // running — any pending suspicion is dropped
        }
        if (oldStates[key].boolValue) {
            // Newly stopped: hold for confirmation on the next poll.
            [stillPending addObject:key];
        } else if ([self.pendingStopKeys containsObject:key]) {
            // Stopped on the previous poll too — confirmed dead.
            [self postNotificationWithBody:
                [NSString stringWithFormat:@"%@ stopped unexpectedly.",
                 [self displayNameForServiceKey:key]]];
        }
    }
    self.pendingStopKeys = stillPending;
}

- (void)postNotificationWithBody:(NSString *)body {
    if (!self.notificationsAllowed) {
        return;
    }
    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = @"Cove";
    content.body = body;
    UNNotificationRequest *request =
        [UNNotificationRequest requestWithIdentifier:[NSUUID UUID].UUIDString
                                             content:content
                                             trigger:nil];
    [[UNUserNotificationCenter currentNotificationCenter]
        addNotificationRequest:request withCompletionHandler:nil];
}

// Async action failures avoid NSAlert on purpose: a modal from an accessory
// app can land behind a full-screen window where it silently blocks the main
// thread. Instead: notification + persistent menu error row + a durable log
// of the full command output at ~/Cove/Logs/menubar.log.
- (void)reportActionFailure:(NSString *)title detail:(NSString *)detail {
    NSString *firstLine = [[detail componentsSeparatedByCharactersInSet:
                            [NSCharacterSet newlineCharacterSet]] firstObject] ?: @"";
    self.lastActionError = title;
    [self postNotificationWithBody:[NSString stringWithFormat:@"%@ — %@", title, firstLine]];
    [self appendToLog:[NSString stringWithFormat:@"%@\n%@\n", title, detail]];
    [self updateMenu];
}

- (void)appendToLog:(NSString *)text {
    NSString *logsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/Logs"];
    NSString *path = [logsDir stringByAppendingPathComponent:@"menubar.log"];
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    NSString *stamped = [NSString stringWithFormat:@"[%@] %@\n",
                         [formatter stringFromDate:[NSDate date]], text];

    NSFileManager *fileManager = [NSFileManager defaultManager];
    [fileManager createDirectoryAtPath:logsDir withIntermediateDirectories:YES
                            attributes:nil error:nil];
    if (![fileManager fileExistsAtPath:path]) {
        [fileManager createFileAtPath:path contents:nil attributes:nil];
    }
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    [handle seekToEndOfFile];
    [handle writeData:[stamped dataUsingEncoding:NSUTF8StringEncoding]];
    [handle closeFile];
}

- (NSString *)displayNameForServiceKey:(NSString *)key {
    if ([key isEqualToString:@"caddy"])   { return @"Caddy"; }
    if ([key isEqualToString:@"mariadb"]) { return @"MariaDB"; }
    if ([key isEqualToString:@"mailpit"]) { return @"Mailpit"; }
    if ([key hasPrefix:@"php-fpm-"]) {
        return [NSString stringWithFormat:@"PHP-FPM %@",
                [key substringFromIndex:[@"php-fpm-" length]]];
    }
    return key;
}

- (BOOL)serviceRunning:(NSString *)key {
    return self.serviceStates[key].boolValue;
}

- (NSInteger)runningServiceCount {
    NSInteger count = 0;
    for (NSNumber *running in self.serviceStates.allValues) {
        if (running.boolValue) {
            count++;
        }
    }
    return count;
}

- (BOOL)allServicesRunning {
    if (!self.statesKnown || self.serviceKeys.count == 0) {
        return NO;
    }
    for (NSString *key in self.serviceKeys) {
        if (!self.serviceStates[key].boolValue) {
            return NO;
        }
    }
    return YES;
}

#pragma mark - Actions

- (void)startCove {
    [self runActionWithArguments:@[@"enable"] actionName:@"start" busyText:@"Starting Cove…"];
}

- (void)stopCove {
    [self runActionWithArguments:@[@"disable"] actionName:@"stop" busyText:@"Stopping Cove…"];
}

// Regenerates the Caddyfile and reloads Caddy — the thing you want after
// hand-editing a directive. (Its /etc/hosts sudo step fails silently in a
// non-interactive shell; that's expected and harmless.)
- (void)reloadCaddy {
    [self runActionWithArguments:@[@"reload"] actionName:@"reload" busyText:@"Reloading Caddy…"];
}

- (void)runActionWithArguments:(NSArray<NSString *> *)arguments
                    actionName:(NSString *)actionName
                      busyText:(NSString *)busyText {
    if (self.busy) {
        return;
    }

    self.busy = YES;
    self.busyText = busyText;
    self.lastError = nil;
    self.lastActionError = nil;
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    [self updateMenu];

    // enable/disable/reload can legitimately take a while on a big install
    // (cert issuance, service restarts), so give them generous headroom.
    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:arguments
                       timeout:120.0
                    completion:^(int status, NSString *output, NSError *error) {
        (void)output;
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.busy = NO;
        strongSelf.busyText = nil;
        strongSelf.lastUserActionTime = CFAbsoluteTimeGetCurrent();
        if (status != 0) {
            NSString *detail = error.localizedDescription ?: @"The Cove command failed.";
            [strongSelf reportActionFailure:[NSString stringWithFormat:@"Could not %@ Cove", actionName]
                                     detail:detail];
            return;
        }

        [strongSelf refreshStatus];
    }];
}

- (void)runCoveWithArguments:(NSArray<NSString *> *)arguments
                     timeout:(NSTimeInterval)timeout
                  completion:(CoveCommandCompletion)completion {
    // Fire the completion at most once, on the main queue. The reader thread
    // and the watchdog both call this; whichever wins, the loser is a no-op.
    // This is what guarantees the app recovers: even if the blocking read
    // below never returns (a subprocess inherited the pipe and outlived cove),
    // the watchdog still fires completion and clears `busy`.
    NSLock *lock = [[NSLock alloc] init];
    __block BOOL finished = NO;
    CoveCommandCompletion finishOnce = ^(int status, NSString *output, NSError *error) {
        [lock lock];
        if (finished) { [lock unlock]; return; }
        finished = YES;
        [lock unlock];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(status, output, error);
        });
    };

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *executable = [self coveExecutablePath];
        NSArray<NSString *> *actualArguments = arguments;
        if ([executable isEqualToString:@"/usr/bin/env"]) {
            actualArguments = [@[@"cove"] arrayByAddingObjectsFromArray:arguments];
        }

        NSTask *task = [[NSTask alloc] init];
        NSPipe *outputPipe = [NSPipe pipe];
        task.executableURL = [NSURL fileURLWithPath:executable];
        task.arguments = actualArguments;
        task.standardOutput = outputPipe;
        task.standardError = outputPipe;

        NSMutableDictionary<NSString *, NSString *> *environment =
            [[[NSProcessInfo processInfo] environment] mutableCopy];
        environment[@"PATH"] =
            @"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
        task.environment = environment;

        NSError *launchError = nil;
        BOOL launched = [task launchAndReturnError:&launchError];
        if (!launched) {
            finishOnce(-1, @"", launchError);
            return;
        }

        // Watchdog: a command that outlives its timeout is wedged. Terminate it
        // (which lets the read below unblock in the common case) and report a
        // timeout now regardless — so a stuck subprocess can't leave the app
        // disabled forever. In the worst case one reader thread lingers on the
        // dead pipe; the app itself stays responsive.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            if (task.isRunning) {
                [task terminate];
            }
            NSError *timeoutError =
                [NSError errorWithDomain:@"CoveMenuBar"
                                    code:-2
                                userInfo:@{NSLocalizedDescriptionKey:
                                    [NSString stringWithFormat:@"Timed out after %.0f seconds.", timeout]}];
            finishOnce(-2, @"", timeoutError);
        });

        NSData *data = [[outputPipe fileHandleForReading] readDataToEndOfFile];
        [task waitUntilExit];
        NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
        int terminationStatus = task.terminationStatus;
        NSError *commandError = nil;

        if (terminationStatus != 0) {
            NSString *message = [output stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (message.length == 0) {
                message = @"The Cove command exited with an error.";
            }
            commandError = [NSError errorWithDomain:@"CoveMenuBar"
                                                code:terminationStatus
                                            userInfo:@{NSLocalizedDescriptionKey: message}];
        }

        finishOnce(terminationStatus, output, commandError);
    });
}

- (NSString *)coveExecutablePath {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    for (NSString *path in @[@"/opt/homebrew/bin/cove", @"/usr/local/bin/cove"]) {
        if ([fileManager isExecutableFileAtPath:path]) {
            return path;
        }
    }
    return @"/usr/bin/env";
}

#pragma mark - Menu skeleton (built once)

- (void)buildMenuSkeleton {
    self.menu = [[NSMenu alloc] init];
    self.menu.autoenablesItems = NO;
    self.menu.delegate = self;

    self.summaryItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    self.summaryItem.enabled = NO;
    [self.menu addItem:self.summaryItem];
    [self.menu addItem:[NSMenuItem separatorItem]];

    // Service rows are inserted at kServiceRowStartIndex by syncServiceRows.

    self.errorItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    self.errorItem.enabled = NO;
    self.errorItem.hidden = YES;
    [self.menu addItem:self.errorItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.actionItem = [[NSMenuItem alloc] initWithTitle:@"Start Cove"
                                                 action:@selector(startCove)
                                          keyEquivalent:@""];
    self.actionItem.target = self;
    [self.menu addItem:self.actionItem];

    self.refreshItem = [[NSMenuItem alloc] initWithTitle:@"Refresh Status"
                                                  action:@selector(refreshStatus)
                                           keyEquivalent:@"r"];
    self.refreshItem.target = self;
    [self.menu addItem:self.refreshItem];

    self.reloadItem = [[NSMenuItem alloc] initWithTitle:@"Reload Caddy"
                                                 action:@selector(reloadCaddy)
                                          keyEquivalent:@""];
    self.reloadItem.target = self;
    [self.menu addItem:self.reloadItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.sitesItem = [[NSMenuItem alloc] initWithTitle:@"Sites" action:nil keyEquivalent:@""];
    self.sitesItem.submenu = [[NSMenu alloc] init];
    self.sitesItem.submenu.autoenablesItems = NO;
    [self.menu addItem:self.sitesItem];
    [self rebuildSitesSubmenu];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.dashboardItem = [self linkItemWithTitle:@"Open Cove Dashboard"
                                          action:@selector(openDashboard)];
    [self.menu addItem:self.dashboardItem];
    self.adminerItem = [self linkItemWithTitle:@"Open Adminer"
                                        action:@selector(openAdminer)];
    [self.menu addItem:self.adminerItem];
    self.mailpitItem = [self linkItemWithTitle:@"Open Mailpit"
                                        action:@selector(openMailpit)];
    [self.menu addItem:self.mailpitItem];
    [self.menu addItem:[self linkItemWithTitle:@"Open Cove Logs"
                                        action:@selector(openLogs)]];
    [self.menu addItem:[self linkItemWithTitle:@"Open Sites Folder"
                                        action:@selector(openSitesFolder)]];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.launchItem = [[NSMenuItem alloc] initWithTitle:@"Launch at Login"
                                                 action:@selector(toggleLaunchAtLogin)
                                          keyEquivalent:@""];
    self.launchItem.target = self;
    [self.menu addItem:self.launchItem];

    self.versionItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    self.versionItem.target = self;
    self.versionItem.enabled = NO;
    self.versionItem.hidden = YES;
    [self.menu addItem:self.versionItem];

    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit Cove Menu Bar"
                                                     action:@selector(quitApp)
                                              keyEquivalent:@"q"];
    quitItem.target = self;
    [self.menu addItem:quitItem];

    self.statusItem.menu = self.menu;
}

#pragma mark - Menu updates (in place)

- (void)updateMenu {
    [self syncBusyPulse];
    [self updateStatusButton];
    [self syncServiceRows];

    self.summaryItem.title = [self summaryText];

    // Action failures outlast status errors: a failed create/start/stop stays
    // visible until the next action, instead of being wiped by the next
    // successful 20s status poll.
    NSString *errorText = self.lastActionError.length > 0 ? self.lastActionError : self.lastError;
    if (errorText.length > 0) {
        NSString *firstLine = [[errorText componentsSeparatedByCharactersInSet:
                                [NSCharacterSet newlineCharacterSet]] firstObject];
        self.errorItem.title = [NSString stringWithFormat:@"Error: %@", firstLine];
        self.errorItem.hidden = NO;
    } else {
        self.errorItem.hidden = YES;
    }

    BOOL allRunning = [self allServicesRunning];
    self.actionItem.title = allRunning ? @"Stop Cove" : @"Start Cove";
    self.actionItem.action = allRunning ? @selector(stopCove) : @selector(startCove);
    self.actionItem.enabled = !self.busy;
    self.refreshItem.enabled = !self.busy;
    self.reloadItem.enabled = !self.busy && [self serviceRunning:@"caddy"];

    self.dashboardItem.enabled = [self serviceRunning:@"caddy"];
    self.adminerItem.enabled = [self serviceRunning:@"caddy"];
    self.mailpitItem.enabled = [self serviceRunning:@"mailpit"];

    self.launchItem.state = SMAppService.mainAppService.status == SMAppServiceStatusEnabled
        ? NSControlStateValueOn
        : NSControlStateValueOff;

    if ([self updateAvailable]) {
        self.versionItem.title = [NSString stringWithFormat:@"Update Cove to v%@…", self.latestVersion];
        self.versionItem.action = @selector(runUpgradeInTerminal);
        self.versionItem.enabled = YES;
        self.versionItem.hidden = NO;
    } else if (self.coveVersion.length > 0) {
        self.versionItem.title = [NSString stringWithFormat:@"Cove v%@", self.coveVersion];
        self.versionItem.action = nil;
        self.versionItem.enabled = NO;
        self.versionItem.hidden = NO;
    } else {
        self.versionItem.hidden = YES;
    }
}

// Keep one menu item per service key, inserting/removing rows only when the
// key set actually changes (e.g. a PHP-FPM pool appears after the first poll
// or a `cove php` pin). Everything else is a title/image mutation, so an open
// menu never re-layouts.
- (void)syncServiceRows {
    if (![self.serviceItemKeys isEqualToArray:self.serviceKeys]) {
        for (NSMenuItem *item in self.serviceItems) {
            [self.menu removeItem:item];
        }
        [self.serviceItems removeAllObjects];

        NSInteger index = kServiceRowStartIndex;
        for (NSString *key in self.serviceKeys) {
            (void)key;
            NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
            item.enabled = NO;
            [self.menu insertItem:item atIndex:index++];
            [self.serviceItems addObject:item];
        }
        self.serviceItemKeys = [self.serviceKeys copy];
    }

    [self.serviceKeys enumerateObjectsUsingBlock:^(NSString *key, NSUInteger idx, BOOL *stop) {
        (void)stop;
        NSMenuItem *item = self.serviceItems[idx];
        NSNumber *state = self.serviceStates[key];
        NSString *stateText = state ? (state.boolValue ? @"Running" : @"Stopped") : @"…";
        NSString *symbol = state
            ? (state.boolValue ? @"checkmark.circle.fill" : @"circle")
            : @"circle.dotted";
        item.title = [NSString stringWithFormat:@"%@: %@",
                      [self displayNameForServiceKey:key], stateText];
        item.image = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:nil];
    }];
}

#pragma mark - Sites submenu

- (NSString *)sitesDirectory {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/Sites"];
}

// Cove's convention: every site is a directory named <name>.localhost inside
// ~/Cove/Sites. The directory also collects loose files (logs, scripts), so
// filter strictly. A cheap readdir on the main thread — sites lists are small.
// Called from menuWillOpen, before the menu is on screen.
//
// Long lists get a "Recent" section: top 5 by the same signal the dashboard's
// modified column uses — mtime of <site>/public, falling back to the site dir.
- (void)rebuildSitesSubmenu {
    NSMenu *submenu = self.sitesItem.submenu;
    [submenu removeAllItems];

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *sitesDir = [self sitesDirectory];
    NSArray<NSString *> *entries =
        [[fileManager contentsOfDirectoryAtPath:sitesDir error:nil]
            sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];

    NSMutableArray<NSDictionary *> *sites = [NSMutableArray array];
    for (NSString *entry in entries) {
        if (![entry hasSuffix:@".localhost"]) {
            continue;
        }
        BOOL isDirectory = NO;
        NSString *sitePath = [sitesDir stringByAppendingPathComponent:entry];
        if (![fileManager fileExistsAtPath:sitePath isDirectory:&isDirectory] || !isDirectory) {
            continue;
        }

        NSString *publicPath = [sitePath stringByAppendingPathComponent:@"public"];
        NSDate *modified = [fileManager attributesOfItemAtPath:publicPath error:nil].fileModificationDate
            ?: [fileManager attributesOfItemAtPath:sitePath error:nil].fileModificationDate
            ?: [NSDate distantPast];
        BOOL isWordPress = [fileManager fileExistsAtPath:
                            [publicPath stringByAppendingPathComponent:@"wp-config.php"]];
        [sites addObject:@{ @"name": entry, @"modified": modified, @"wp": @(isWordPress) }];
    }

    if (sites.count >= 8) {
        NSArray<NSDictionary *> *recent =
            [[sites sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                return [b[@"modified"] compare:a[@"modified"]];
            }] subarrayWithRange:NSMakeRange(0, 5)];

        NSMenuItem *recentHeader = [[NSMenuItem alloc] initWithTitle:@"Recent"
                                                              action:nil
                                                       keyEquivalent:@""];
        recentHeader.enabled = NO;
        [submenu addItem:recentHeader];
        for (NSDictionary *site in recent) {
            [self addItemsForSite:site[@"name"] isWordPress:[site[@"wp"] boolValue] toMenu:submenu];
        }
        [submenu addItem:[NSMenuItem separatorItem]];
    }

    for (NSDictionary *site in sites) {
        [self addItemsForSite:site[@"name"] isWordPress:[site[@"wp"] boolValue] toMenu:submenu];
    }

    if (sites.count > 0) {
        [submenu addItem:[NSMenuItem separatorItem]];
        self.sitesItem.title = [NSString stringWithFormat:@"Sites (%lu)", (unsigned long)sites.count];
    } else {
        self.sitesItem.title = @"Sites";
    }

    NSMenuItem *newSiteItem = [[NSMenuItem alloc] initWithTitle:@"New Site…"
                                                         action:@selector(promptForNewSite)
                                                  keyEquivalent:@""];
    newSiteItem.target = self;
    newSiteItem.enabled = !self.busy;
    [submenu addItem:newSiteItem];
}

- (void)addItemsForSite:(NSString *)entry isWordPress:(BOOL)isWordPress toMenu:(NSMenu *)submenu {
    NSMenuItem *siteItem = [[NSMenuItem alloc] initWithTitle:entry
                                                      action:@selector(openSite:)
                                               keyEquivalent:@""];
    siteItem.target = self;
    siteItem.representedObject = entry;
    [submenu addItem:siteItem];

    // WordPress sites get an option-key alternate that generates a
    // one-time admin login via `cove login`.
    if (isWordPress) {
        NSMenuItem *loginItem =
            [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Log in to %@", entry]
                                      action:@selector(loginToSite:)
                               keyEquivalent:@""];
        loginItem.target = self;
        loginItem.representedObject = entry;
        loginItem.keyEquivalentModifierMask = NSEventModifierFlagOption;
        loginItem.alternate = YES;
        [submenu addItem:loginItem];
    }
}

#pragma mark - New site

- (void)promptForNewSite {
    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"New Cove Site";
    alert.informativeText = @"Creates a WordPress site at <name>.localhost.\n"
                             "Lowercase letters, numbers, and hyphens only.";
    [alert addButtonWithTitle:@"Create"];
    [alert addButtonWithTitle:@"Cancel"];

    NSTextField *field = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 230, 24)];
    field.placeholderString = @"my-new-site";
    alert.accessoryView = field;
    alert.window.initialFirstResponder = field;

    if ([alert runModal] != NSAlertFirstButtonReturn) {
        return;
    }

    NSString *name = [[field.stringValue lowercaseString] stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (name.length == 0) {
        return;
    }

    // Mirror cove add's own validation so obvious typos fail fast with a
    // clear message instead of a shell error.
    NSRegularExpression *valid =
        [NSRegularExpression regularExpressionWithPattern:@"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
                                                  options:0
                                                    error:nil];
    if (![valid firstMatchInString:name options:0 range:NSMakeRange(0, name.length)]) {
        [self showErrorWithTitle:@"Invalid site name"
                         message:@"Site names can only contain lowercase letters, numbers, and "
                                  "hyphens, and cannot begin or end with a hyphen."];
        return;
    }

    if (self.busy) {
        return;
    }
    self.busy = YES;
    self.busyText = [NSString stringWithFormat:@"Creating %@.localhost… (takes about a minute)", name];
    self.lastActionError = nil;
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    [self updateMenu];

    // A full WordPress install (core download + DB + install + reload) runs a
    // minute or more; allow four before treating it as wedged.
    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:@[@"add", name]
                       timeout:240.0
                    completion:^(int status, NSString *output, NSError *error) {
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.busy = NO;
        strongSelf.busyText = nil;
        strongSelf.lastUserActionTime = CFAbsoluteTimeGetCurrent();
        if (status != 0) {
            [strongSelf reportActionFailure:[NSString stringWithFormat:@"Could not create %@.localhost", name]
                                     detail:(error.localizedDescription.length > 0
                                             ? error.localizedDescription
                                             : (output.length > 0 ? output : @"cove add exited with an error."))];
            return;
        }

        [strongSelf postNotificationWithBody:
            [NSString stringWithFormat:@"%@.localhost is ready — opening it now.", name]];
        [strongSelf refreshStatus];
        [strongSelf openCoveHost:[name stringByAppendingString:@".localhost"]];
    }];
}

- (void)openSite:(NSMenuItem *)sender {
    NSString *host = sender.representedObject;
    if (host.length > 0) {
        [self openCoveHost:host];
    }
}

- (void)loginToSite:(NSMenuItem *)sender {
    NSString *host = sender.representedObject;
    if (host.length == 0) {
        return;
    }
    // Guard against a second click while wp-cli is still minting the URL:
    // each `cove login` run regenerates the one-time token, so a parallel run
    // would invalidate the first URL right before its tab opens.
    if (self.busy) {
        return;
    }
    self.busy = YES;
    self.busyText = [NSString stringWithFormat:@"Logging in to %@…", host];
    self.lastActionError = nil;
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    [self updateMenu];

    // `cove login` takes the site name without the .localhost suffix and
    // prints a one-time login URL inside a decorative gum box.
    NSString *siteName = [host stringByReplacingOccurrencesOfString:@".localhost"
                                                         withString:@""
                                                            options:NSAnchoredSearch | NSBackwardsSearch
                                                              range:NSMakeRange(0, host.length)];

    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:@[@"login", siteName]
                       timeout:45.0
                    completion:^(int status, NSString *output, NSError *error) {
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.busy = NO;
        strongSelf.busyText = nil;
        strongSelf.lastUserActionTime = CFAbsoluteTimeGetCurrent();

        NSString *loginURL = nil;
        if (status == 0) {
            // stdout and stderr are merged, so wp-cli/PHP notices (which often
            // print their own https:// URLs) can appear before the real login
            // line. Don't take the first URL — take the one that actually
            // points at THIS site's login endpoint. Charset widened so a token
            // containing ~ # + ! @ isn't truncated mid-URL.
            NSRegularExpression *regex =
                [NSRegularExpression regularExpressionWithPattern:@"https://[A-Za-z0-9.:/_?=&%~#+!@-]+"
                                                          options:0
                                                            error:nil];
            for (NSTextCheckingResult *match in
                 [regex matchesInString:output options:0 range:NSMakeRange(0, output.length)]) {
                NSString *candidate = [output substringWithRange:match.range];
                if ([candidate containsString:host] && [candidate containsString:@"wp-login"]) {
                    loginURL = candidate;   // keep scanning; last match wins
                }
            }
        }

        if (loginURL) {
            [strongSelf updateMenu];
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:loginURL]];
        } else {
            [strongSelf reportActionFailure:[NSString stringWithFormat:@"Could not log in to %@", host]
                                     detail:error.localizedDescription
                                            ?: @"cove login did not return a login URL."];
        }
    }];
}

- (void)openSitesFolder {
    NSURL *sitesURL = [NSURL fileURLWithPath:[self sitesDirectory] isDirectory:YES];
    [[NSWorkspace sharedWorkspace] openURL:sitesURL];
}

#pragma mark - Update check

// Resolve the latest released version by following the GitHub redirect for
// releases/latest → .../releases/tag/v<version>. No API token, no rate-limit
// concerns at once a day, and no JSON parsing needed.
- (void)checkForUpdates {
    NSURL *url = [NSURL URLWithString:@"https://github.com/anchorhost/cove/releases/latest"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"HEAD";
    request.timeoutInterval = 15.0;

    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
              (void)data;
              if (error || !response.URL) {
                  return;
              }
              NSString *tag = response.URL.lastPathComponent;
              if (![tag hasPrefix:@"v"] || tag.length < 2) {
                  return;
              }
              NSString *version = [tag substringFromIndex:1];
              dispatch_async(dispatch_get_main_queue(), ^{
                  AppDelegate *strongSelf = weakSelf;
                  if (!strongSelf) {
                      return;
                  }
                  strongSelf.latestVersion = version;
                  [strongSelf updateMenu];
              });
          }];
    [task resume];
}

- (BOOL)updateAvailable {
    if (self.coveVersion.length == 0 || self.latestVersion.length == 0) {
        return NO;
    }
    return [self compareVersion:self.latestVersion to:self.coveVersion] == NSOrderedDescending;
}

// Numeric segment-by-segment comparison, so 1.10 > 1.9.
- (NSComparisonResult)compareVersion:(NSString *)a to:(NSString *)b {
    NSArray<NSString *> *aParts = [a componentsSeparatedByString:@"."];
    NSArray<NSString *> *bParts = [b componentsSeparatedByString:@"."];
    NSUInteger count = MAX(aParts.count, bParts.count);
    for (NSUInteger i = 0; i < count; i++) {
        NSInteger aValue = i < aParts.count ? aParts[i].integerValue : 0;
        NSInteger bValue = i < bParts.count ? bParts[i].integerValue : 0;
        if (aValue != bValue) {
            return aValue > bValue ? NSOrderedDescending : NSOrderedAscending;
        }
    }
    return NSOrderedSame;
}

// `cove upgrade` can install Homebrew packages and ask questions — that
// belongs in a real terminal, not a headless NSTask. A .command file opens in
// Terminal via Launch Services with no automation (TCC) prompt.
- (void)runUpgradeInTerminal {
    // The upgrade restarts services from the Terminal window over the next
    // couple of minutes; mark it as user-initiated so the poll landing in the
    // middle of it doesn't read the churn as a crash.
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    NSString *script = @"#!/bin/zsh\n"
                        "export PATH=\"/opt/homebrew/bin:/usr/local/bin:$PATH\"\n"
                        "cove upgrade\n";
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"cove-upgrade.command"];
    NSError *error = nil;
    if (![script writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        [self showErrorWithTitle:@"Update Cove" message:error.localizedDescription];
        return;
    }
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @0755}
                                     ofItemAtPath:path
                                            error:nil];
    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:path]];
}

#pragma mark - Status button

- (void)syncBusyPulse {
    if (self.busy && !self.busyPulseTimer) {
        self.busyPulseTimer = [NSTimer scheduledTimerWithTimeInterval:0.6
                                                              target:self
                                                            selector:@selector(pulseTick)
                                                            userInfo:nil
                                                             repeats:YES];
    } else if (!self.busy && self.busyPulseTimer) {
        [self.busyPulseTimer invalidate];
        self.busyPulseTimer = nil;
        self.pulsePhase = NO;
    }
}

- (void)pulseTick {
    self.pulsePhase = !self.pulsePhase;
    [self updateStatusButton];
}

- (void)updateStatusButton {
    NSStatusBarButton *button = self.statusItem.button;
    if (!button) {
        return;
    }

    NSImage *image;
    if (self.busy) {
        // Alternate full-color / grayscale while an action runs — a visible
        // heartbeat that distinguishes "working" from "hung".
        image = self.pulsePhase ? self.partialImage : self.runningImage;
    } else if ([self allServicesRunning] && self.lastError.length == 0) {
        image = self.runningImage;
    } else if ([self runningServiceCount] > 0) {
        image = self.partialImage;
    } else {
        image = self.stoppedImage;
    }

    if (image) {
        button.title = @"";
        button.image = image;
        button.imagePosition = NSImageOnly;
    } else {
        // Icon decode failed (loadStatusImages guards against a macOS whose
        // ImageIO can't rasterize the SVG) — fall back to a text item rather
        // than an invisible one.
        button.title = @"Cove";
        button.image = nil;
        button.imagePosition = NSNoImage;
    }
    button.toolTip = [self summaryText];
    button.accessibilityLabel = [self summaryText];
}

- (void)loadStatusImages {
    // The vector logo — the same mark the dashboard renders. NSImage decoding
    // SVG is undocumented Apple behavior (CoreSVG, observed working since
    // macOS 11); if it ever fails, the images stay nil and updateStatusButton
    // falls back to a "Cove" text item instead of an invisible one.
    NSURL *assetURL = [[NSBundle mainBundle] URLForResource:@"cove-logo"
                                             withExtension:@"svg"
                                              subdirectory:@"Assets"];
    NSImage *source = assetURL ? [[NSImage alloc] initWithContentsOfURL:assetURL] : nil;
    if (!source || ![self imageDrawsVisibly:source]) {
        return;
    }

    source.size = NSMakeSize(18, 18);
    self.runningImage = source;
    self.partialImage = [self imageByDesaturating:source brightness:0.02 contrast:1.05];
    self.stoppedImage = [self imageByDesaturating:source brightness:-0.12 contrast:1.20];
}

// CoreSVG can "succeed" on an SVG yet hand back a non-nil image with no
// usable content (observed with viewBox-only SVGs on some macOS builds) —
// which would put an invisible status item in the menu bar. Rasterize a
// probe and require at least one visible pixel before trusting the icon.
- (BOOL)imageDrawsVisibly:(NSImage *)image {
    const NSInteger side = 18;
    NSBitmapImageRep *rep = [[NSBitmapImageRep alloc]
        initWithBitmapDataPlanes:NULL
                      pixelsWide:side
                      pixelsHigh:side
                   bitsPerSample:8
                 samplesPerPixel:4
                        hasAlpha:YES
                        isPlanar:NO
                  colorSpaceName:NSCalibratedRGBColorSpace
                     bytesPerRow:0
                    bitsPerPixel:0];
    if (!rep || !rep.bitmapData) {
        return NO;
    }
    memset(rep.bitmapData, 0, (size_t)(rep.bytesPerRow * side));

    NSGraphicsContext *context =
        [NSGraphicsContext graphicsContextWithBitmapImageRep:rep];
    if (!context) {
        return NO;
    }
    [NSGraphicsContext saveGraphicsState];
    [NSGraphicsContext setCurrentContext:context];
    [image drawInRect:NSMakeRect(0, 0, side, side)
             fromRect:NSZeroRect
            operation:NSCompositingOperationSourceOver
             fraction:1.0];
    [NSGraphicsContext restoreGraphicsState];

    const unsigned char *data = rep.bitmapData;
    NSInteger byteCount = rep.bytesPerRow * side;
    for (NSInteger i = 0; i < byteCount; i++) {
        if (data[i] != 0) {
            return YES;
        }
    }
    return NO;
}

- (NSImage *)imageByDesaturating:(NSImage *)source
                      brightness:(CGFloat)brightness
                        contrast:(CGFloat)contrast {
    NSData *sourceData = [source TIFFRepresentation];
    CIImage *inputImage = sourceData ? [CIImage imageWithData:sourceData] : nil;
    if (!inputImage) {
        return source;
    }

    CIFilter *filter = [CIFilter filterWithName:@"CIColorControls"];
    [filter setValue:inputImage forKey:kCIInputImageKey];
    [filter setValue:@0.0 forKey:kCIInputSaturationKey];
    [filter setValue:@(brightness) forKey:kCIInputBrightnessKey];
    [filter setValue:@(contrast) forKey:kCIInputContrastKey];

    CIImage *outputImage = filter.outputImage;
    if (!outputImage) {
        return source;
    }

    CIContext *context = [CIContext contextWithOptions:nil];
    CGImageRef cgImage = [context createCGImage:outputImage fromRect:outputImage.extent];
    if (!cgImage) {
        return source;
    }

    NSImage *result = [[NSImage alloc] initWithCGImage:cgImage size:NSMakeSize(18, 18)];
    CGImageRelease(cgImage);
    return result;
}

- (NSString *)summaryText {
    if (self.busy) {
        return self.busyText.length > 0 ? self.busyText : @"Cove is updating…";
    }
    if (self.lastError.length > 0) {
        return @"Cove status unavailable";
    }
    if (!self.statesKnown) {
        return @"Checking Cove status...";
    }
    if ([self allServicesRunning]) {
        return @"Cove is running";
    }
    if ([self runningServiceCount] > 0) {
        return @"Cove is partially running";
    }
    return @"Cove is stopped";
}

- (NSMenuItem *)linkItemWithTitle:(NSString *)title action:(SEL)action {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:@""];
    item.target = self;
    return item;
}

#pragma mark - Quick links

- (void)openDashboard {
    [self openCoveHost:@"cove.localhost"];
}

- (void)openAdminer {
    [self openCoveHost:@"db.cove.localhost"];
}

- (void)openMailpit {
    [self openCoveHost:@"mail.cove.localhost"];
}

- (void)openCoveHost:(NSString *)host {
    NSString *urlString = [NSString stringWithFormat:@"https://%@%@", host, [self httpsPortSuffix]];
    NSURL *url = [NSURL URLWithString:urlString];
    if (url) {
        [[NSWorkspace sharedWorkspace] openURL:url];
    }
}

- (NSString *)httpsPortSuffix {
    NSString *configPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/config"];
    NSString *config = [NSString stringWithContentsOfFile:configPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
    if (!config) {
        return @"";
    }

    NSString *port = nil;
    for (NSString *line in [config componentsSeparatedByCharactersInSet:
                            [NSCharacterSet newlineCharacterSet]]) {
        if ([line hasPrefix:@"HTTPS_PORT="]) {
            port = [[line substringFromIndex:[@"HTTPS_PORT=" length]]
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet characterSetWithCharactersInString:@"'\" "]];
        }
    }

    if (port.length == 0 || [port isEqualToString:@"443"]) {
        return @"";
    }
    return [@":" stringByAppendingString:port];
}

- (void)openLogs {
    NSURL *logsURL = [NSURL fileURLWithPath:
        [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/Logs"]
                               isDirectory:YES];
    [[NSWorkspace sharedWorkspace] openURL:logsURL];
}

#pragma mark - Housekeeping

- (void)toggleLaunchAtLogin {
    SMAppService *service = SMAppService.mainAppService;
    NSError *error = nil;
    BOOL succeeded;
    if (service.status == SMAppServiceStatusEnabled) {
        succeeded = [service unregisterAndReturnError:&error];
    } else {
        succeeded = [service registerAndReturnError:&error];
    }

    if (!succeeded) {
        [self showErrorWithTitle:@"Launch at Login"
                         message:error.localizedDescription ?: @"Unable to change the login item."];
    }
    [self updateMenu];
}

- (void)showErrorWithTitle:(NSString *)title message:(NSString *)message {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleWarning;
    alert.messageText = title;
    alert.informativeText = message;
    // Accessory apps have no key window; without activation the alert can
    // appear behind whatever the user is working in.
    [NSApp activateIgnoringOtherApps:YES];
    [alert runModal];
}

- (void)quitApp {
    [NSApp terminate:nil];
}

@end

int main(int argc, const char *argv[]) {
    // `CoveMenuBar unregister` — invoked by `cove menubar disable` before the
    // bundle is deleted, because SMAppService login items can only be
    // unregistered from inside the app they belong to. Without this, disable
    // would leave a stale entry in System Settings → Login Items.
    if (argc > 1 && strcmp(argv[1], "unregister") == 0) {
        @autoreleasepool {
            [SMAppService.mainAppService unregisterAndReturnError:nil];
        }
        return 0;
    }

    @autoreleasepool {
        NSApplication *application = [NSApplication sharedApplication];
        // NSApplication does not retain its delegate, and ARC may release a
        // local as soon as its last use passes — before the run loop delivers
        // applicationDidFinishLaunching:. A static keeps the delegate alive
        // for the life of the process; without it the app can launch as a
        // healthy event loop that never creates its status item.
        static AppDelegate *delegate;
        delegate = [[AppDelegate alloc] init];
        application.delegate = delegate;
        [application run];
    }
    return 0;
}
