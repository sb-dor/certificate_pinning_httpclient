#import "CertificatePinningHttpClientPlugin.h"

@interface HostCertificatesFetcher: NSObject<NSURLSessionTaskDelegate>

@property(strong) NSArray<FlutterStandardTypedData *> *hostCertificates;

- (NSArray<FlutterStandardTypedData *> *)fetchCertificates:(NSURL *)url;

@end

static const NSTimeInterval FETCH_CERTIFICATES_TIMEOUT = 3;

@implementation CertificatePinningHttpClientPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    FlutterMethodChannel* channel = [[FlutterMethodChannel alloc]
                 initWithName: @"certificate_pinning_httpclient"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]];
    CertificatePinningHttpClientPlugin* instance = [[CertificatePinningHttpClientPlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if ([@"fetchHostCertificates" isEqualToString:call.method]) {
        NSURL *url = [NSURL URLWithString:call.arguments[@"url"]];
        if (url == nil) {
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:NSURLErrorDomain
                details:[NSString stringWithFormat:@"Fetch host certificates invalid URL: %@", call.arguments[@"url"]]]);
        } else {
            HostCertificatesFetcher *hostCertificatesFetcher = [[HostCertificatesFetcher alloc] init];
            NSArray<FlutterStandardTypedData *> *hostCerts = [hostCertificatesFetcher fetchCertificates:url];
            result(hostCerts);
        }
    } else {
        result(FlutterMethodNotImplemented);
    }
}

@end

@implementation HostCertificatesFetcher

- (NSArray<FlutterStandardTypedData *> *)fetchCertificates:(NSURL *)url
{
    _hostCertificates = nil;

    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    sessionConfig.timeoutIntervalForResource = FETCH_CERTIFICATES_TIMEOUT;
    NSURLSession* URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];

    NSMutableURLRequest *certFetchRequest = [NSMutableURLRequest requestWithURL:url];
    [certFetchRequest setTimeoutInterval:FETCH_CERTIFICATES_TIMEOUT];
    [certFetchRequest setHTTPMethod:@"GET"];

    dispatch_semaphore_t certFetchComplete = dispatch_semaphore_create(0);

    __block NSError *certFetchError = nil;
    NSURLSessionTask *certFetchTask = [URLSession dataTaskWithRequest:certFetchRequest
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
        {
            certFetchError = error;
            dispatch_semaphore_signal(certFetchComplete);
        }];

    [certFetchTask resume];
    dispatch_semaphore_wait(certFetchComplete, DISPATCH_TIME_FOREVER);
    [URLSession invalidateAndCancel];

    if (!certFetchError) {
        NSLog(@"Failed to get host certificates: Error: unknown\n");
        return nil;
    }
    if (certFetchError && (certFetchError.code != NSURLErrorCancelled)) {
        NSLog(@"Failed to get host certificates: Error: %@\n", certFetchError.localizedDescription);
        return nil;
    }

    return _hostCertificates;
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (!serverTrust) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    CFErrorRef trustError = NULL;
    Boolean isTrusted = SecTrustEvaluateWithError(serverTrust, &trustError);
    if (trustError) {
        CFRelease(trustError);
    }
    if (!isTrusted) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // SecTrustCopyCertificateChain is only available on macOS 12+, so keep the
    // older accessors while this plugin supports macOS 10.14.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray arrayWithCapacity:(NSUInteger)certCount];
    for (int certIndex = 0; certIndex < certCount; certIndex++) {
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, certIndex);
        if (!cert) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
        NSData *certData = (NSData *) CFBridgingRelease(SecCertificateCopyData(cert));
        FlutterStandardTypedData *certFSTD = [FlutterStandardTypedData typedDataWithBytes:certData];
        [certs addObject:certFSTD];
    }
#pragma clang diagnostic pop

    _hostCertificates = certs;
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

@end
