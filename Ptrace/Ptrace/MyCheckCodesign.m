//
//  MyCheckCodesign.m
//  Ptrace
//
//  Created by cib on 2023/4/21.
//

#import "MyCheckCodesign.h"

@implementation MyCheckCodesign

+(void)load{
    NSLog(@"******************* FrameWork load ****************");
    safeStringHandle();
}

#define Str_Key 0xAD
//查看embedded.mobileprovision信息security cms -D -i embedded.mobileprovision
//找到<key>application-identifier</key>的value的第一部分（即.com 前面的字条串）
//把字符串3748LX2W73变成函数隐藏原来的字符串
//以下实际返回3748LX2W73
//23P8M9VEK5
static NSString *subStr4(void){
    unsigned char key[] = {//用异或^运算进行加密
        (Str_Key ^'2'),
        (Str_Key ^'3'),
        (Str_Key ^'P'),
        (Str_Key ^'8'),
        (Str_Key ^'M'),
        (Str_Key ^'9'),
        (Str_Key ^'V'),
        (Str_Key ^'E'),
        (Str_Key ^'K'),
        (Str_Key ^'5'),
        (Str_Key ^'\0'),
    };
    
    //用异或^运算进行解密
    unsigned char *p = key;
    while (((*p) ^= Str_Key) != '\0') {
        p++;
    };
    
    return [NSString stringWithUTF8String:(const char *)key];
}

//以下实际返回 embedded
static NSString *subStr1(void){
    unsigned char key[] = {//用异或^运算进行加密
        (Str_Key ^'e'),
        (Str_Key ^'m'),
        (Str_Key ^'b'),
        (Str_Key ^'e'),
        (Str_Key ^'d'),
        (Str_Key ^'d'),
        (Str_Key ^'e'),
        (Str_Key ^'d'),
        (Str_Key ^'\0'),
    };
    
    //用异或^运算进行解密
    unsigned char *p = key;
    while (((*p) ^= Str_Key) != '\0') {
        p++;
    };
    
    return [NSString stringWithUTF8String:(const char *)key];
}

//以下实际返回 mobileprovision
static NSString *subStr2(void){
    unsigned char key[] = {//用异或^运算进行加密
        (Str_Key ^'m'),
        (Str_Key ^'o'),
        (Str_Key ^'b'),
        (Str_Key ^'i'),
        (Str_Key ^'l'),
        (Str_Key ^'e'),
        (Str_Key ^'p'),
        (Str_Key ^'r'),
        (Str_Key ^'o'),
        (Str_Key ^'v'),
        (Str_Key ^'i'),
        (Str_Key ^'s'),
        (Str_Key ^'i'),
        (Str_Key ^'o'),
        (Str_Key ^'n'),
        (Str_Key ^'\0'),
    };
    
    //用异或^运算进行解密
    unsigned char *p = key;
    while (((*p) ^= Str_Key) != '\0') {
        p++;
    };

    return [NSString stringWithUTF8String:(const char *)key];
}


//以下实际返回  application-identifier
static NSString *subStr5(void){
    unsigned char key[] = {//用异或^运算进行加密
        (Str_Key ^'a'),
        (Str_Key ^'p'),
        (Str_Key ^'p'),
        (Str_Key ^'l'),
        (Str_Key ^'i'),
        (Str_Key ^'c'),
        (Str_Key ^'a'),
        (Str_Key ^'t'),
        (Str_Key ^'i'),
        (Str_Key ^'o'),
        (Str_Key ^'n'),
        (Str_Key ^'-'),
        (Str_Key ^'i'),
        (Str_Key ^'d'),
        (Str_Key ^'e'),
        (Str_Key ^'n'),
        (Str_Key ^'t'),
        (Str_Key ^'i'),
        (Str_Key ^'f'),
        (Str_Key ^'i'),
        (Str_Key ^'e'),
        (Str_Key ^'r'),
        (Str_Key ^'\0'),
    };
    
    //用异或^运算进行解密
    unsigned char *p = key;
    while (((*p) ^= Str_Key) != '\0') {
        p++;
    };
    
    return [NSString stringWithUTF8String:(const char *)key];
}

//以下实际返回  //com.apple.developer.team-identifier
static NSString *subStr3(void){
    unsigned char key[] = {//用异或^运算进行加密
        (Str_Key ^'c'),
        (Str_Key ^'o'),
        (Str_Key ^'m'),
        (Str_Key ^'.'),
        (Str_Key ^'a'),
        (Str_Key ^'p'),
        (Str_Key ^'p'),
        (Str_Key ^'l'),
        (Str_Key ^'e'),
        (Str_Key ^'.'),
        
        (Str_Key ^'d'),
        (Str_Key ^'e'),
        (Str_Key ^'v'),
        (Str_Key ^'e'),
        (Str_Key ^'l'),
        (Str_Key ^'o'),
        (Str_Key ^'p'),
        (Str_Key ^'e'),
        (Str_Key ^'r'),
        (Str_Key ^'.'),
        
        (Str_Key ^'t'),
        (Str_Key ^'e'),
        (Str_Key ^'a'),
        (Str_Key ^'m'),

        
        (Str_Key ^'-'),
        (Str_Key ^'i'),
        (Str_Key ^'d'),
        (Str_Key ^'e'),
        (Str_Key ^'n'),
        (Str_Key ^'t'),
        (Str_Key ^'i'),
        (Str_Key ^'f'),
        (Str_Key ^'i'),
        (Str_Key ^'e'),
        (Str_Key ^'r'),
        (Str_Key ^'\0'),
    };
    
    //用异或^运算进行解密
    unsigned char *p = key;
    while (((*p) ^= Str_Key) != '\0') {
        p++;
    };
    
    return [NSString stringWithUTF8String:(const char *)key];
}


// 以下函数名实为checkCodesign(),但为了安全故意伪装成字符串处理函数
void safeStringHandle(void){
    // 描述文件路径
    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:subStr1() ofType:subStr2()];
    // 读取application-identifier  注意描述文件的编码要使用:NSASCIIStringEncoding
    NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:NSASCIIStringEncoding error:nil];
    NSArray *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

    for (int i = 0; i < embeddedProvisioningLines.count; i++) {
        if ([embeddedProvisioningLines[i] rangeOfString:subStr3()].location != NSNotFound) {

            NSInteger fromPosition = [embeddedProvisioningLines[i+1] rangeOfString:@"<string>"].location+8;

            NSInteger toPosition = [embeddedProvisioningLines[i+1] rangeOfString:@"</string>"].location;

            NSRange range;
            range.location = fromPosition;
            range.length = toPosition - fromPosition;

            NSString *fullIdentifier = [embeddedProvisioningLines[i+1] substringWithRange:range];
//            NSArray *identifierComponents = [fullIdentifier componentsSeparatedByString:@"."];
//            NSString *appIdentifier = [identifierComponents firstObject];

            // 对比签名ID
            if (![fullIdentifier isEqual:subStr4()]) {
                // 以下汇编相当于 exit(0)
                    #ifdef __arm64__
                        asm volatile(
                            "mov X0,#0\n"
                            "mov x16,#1\n"
                            "svc #0x80"
                            );
                    #endif
                    #ifdef __arm__
                        asm volatile(
                            "mov r0,#0\n"
                            "mov r12,#1\n"
                            "svc #80"
                            );
                    #endif
            }
            break;
        }
    }
}

@end
