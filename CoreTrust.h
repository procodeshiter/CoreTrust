#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <mach-o/loader.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <objc/runtime.h>

#define kMSV1 "/System/Library/PrivateFrameworks/MobileSystemServices.framework/MobileSystemServices"
#define kCoreTrust "/System/Library/PrivateFrameworks/CoreTrust.framework/CoreTrust"

typedef struct __SecCode *SecCodeRef;
typedef struct __SecRequirement *SecRequirementRef;

static BOOL (*original_CTEvaluateAMDCert)(void *cert, void *policy, void *error);
static BOOL hooked_CTEvaluateAMDCert(void *cert, void *policy, void *error) {
    return YES;
}

static int (*original_MISValidateSignature)(void *unknown, void *archive, void *signature, void *teamID);
static int hooked_MISValidateSignature(void *unknown, void *archive, void *signature, void *teamID) {
    return 0;
}

void applyCoreTrustHooks() {
    void *handle = dlopen(kCoreTrust, RTLD_NOW);
    if (handle) {
        void *sym = dlsym(handle, "CTEvaluateAMDCert");
        if (sym) {
            MSHookFunction(sym, (void *)hooked_CTEvaluateAMDCert, (void **)&original_CTEvaluateAMDCert);
        }
        dlclose(handle);
    }
    
    handle = dlopen("/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation", RTLD_NOW);
    if (handle) {
        void *sym = dlsym(handle, "MISValidateSignature");
        if (sym) {
            MSHookFunction(sym, (void *)hooked_MISValidateSignature, (void **)&original_MISValidateSignature);
        }
        dlclose(handle);
    }
}

int installApplication(NSString *path, NSString *bundleId) {
    void *msv1 = dlopen(kMSV1, RTLD_LAZY);
    if (!msv1) return -1;
    
    MobileInstallationInstall installFunc = (MobileInstallationInstall)dlsym(msv1, "MobileInstallationInstall");
    if (!installFunc) {
        dlclose(msv1);
        return -2;
    }
    
    NSDictionary *options = @{
        @"CFBundleIdentifier": bundleId,
        @"PackageType": @"Application",
        @"SkipVerification": @YES
    };
    
    int result = installFunc((__bridge CFStringRef)path, (__bridge CFDictionaryRef)options, NULL, NULL);
    dlclose(msv1);
    
    return result;
}

BOOL injectTrustCache(NSString *binaryPath) {
    NSData *cdHash = computeCDHash(binaryPath);
    if (!cdHash) return NO;
    
    NSString *cmd = [NSString stringWithFormat:@"/usr/bin/sqlite3 /var/mobile/Library/Preferences/com.apple.security.plist \"INSERT OR REPLACE INTO cdpd (cdhash) VALUES (X'%@');\"", 
                    [cdHash hexadecimalString]];
    
    return system([cmd UTF8String]) == 0;
}

NSData* computeCDHash(NSString *path) {
    NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!file) return nil;
    
    NSData *data = [file readDataToEndOfFile];
    [file closeFile];
    
    const struct mach_header *header = (struct mach_header *)[data bytes];
    uint8_t *ptr = (uint8_t *)header + sizeof(struct mach_header);
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *cmd = (struct load_command *)ptr;
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *sigCmd = (struct linkedit_data_command *)ptr;
            uint8_t *sigStart = (uint8_t *)header + sigCmd->dataoff;
            
            CS_SuperBlob *superblob = (CS_SuperBlob *)sigStart;
            if (superblob->magic != 0xfade0cc0) continue;
            
            for (uint32_t j = 0; j < superblob->count; j++) {
                CS_BlobIndex index = superblob->index[j];
                if (index.type == 0xfade0c02) {
                    CS_CodeDirectory *cd = (CS_CodeDirectory *)((uint8_t *)superblob + index.offset);
                    
                    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
                    CC_SHA256(cd, cd->length, hash);
                    
                    return [NSData dataWithBytes:hash length:20];
                }
            }
        }
        ptr += cmd->cmdsize;
    }
    return nil;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        NSLog(@"Usage: %s <ipa_path> <bundle_id>", argv[0]);
        return -1;
    }
    
    if (getuid() != 0) {
        NSLog(@"This tool requires root privileges!");
        return -1;
    }
    
    NSString *ipaPath = [NSString stringWithUTF8String:argv[1]];
    NSString *bundleId = [NSString stringWithUTF8String:argv[2]];
    
    applyCoreTrustHooks();
    
    if (!injectTrustCache(ipaPath)) {
        NSLog(@"Failed to inject into trust cache");
        return -1;
    }
    
    int result = installApplication(ipaPath, bundleId);
    if (result == 0) {
        NSLog(@"Application installed successfully!");
    } else {
        NSLog(@"Installation failed with error: %d", result);
    }
    
    return result;
    }
