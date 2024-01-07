
#ifdef RCT_NEW_ARCH_ENABLED
#import "RNSeaUtilSpec.h"

@interface SeaUtil : NSObject <NativeSeaUtilSpec>
#else
#import <React/RCTBridgeModule.h>

@interface SeaUtil : NSObject <RCTBridgeModule>
#endif

@end
