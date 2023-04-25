//
//  InjectJailbroken.m
//  Ptrace
//
//  Created by cib on 2023/4/21.
//

// 防越狱
// 1.在 Other Linker Flags 中添加 : -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null 即可 ( 这个指令不能写错 , 写错会直接影响越狱插件能否注入成功 ) .
// 参考链接：https://juejin.cn/post/6844904143979560974

#import "InjectJailbroken.h"
#import <mach-o/loader.h>
#import <mach-o/dyld.h>

#if __LP64__
#define LC_SEGMENT_COMMAND        LC_SEGMENT_64
#define LC_SEGMENT_COMMAND_WRONG  LC_SEGMENT
#define LC_ENCRYPT_COMMAND        LC_ENCRYPTION_INFO
#define macho_segment_command     segment_command_64
#define macho_section             section_64
#define macho_header              mach_header_64
#else
#define macho_header              mach_header
#define LC_SEGMENT_COMMAND        LC_SEGMENT
#define LC_SEGMENT_COMMAND_WRONG  LC_SEGMENT_64
#define LC_ENCRYPT_COMMAND        LC_ENCRYPTION_INFO_64
#define macho_segment_command     segment_command
#define macho_section             section
#endif

@implementation InjectJailbroken

+ (void)load {
    // imagelist 里第0个是我们自己的可执行文件
    const struct mach_header *header = _dyld_get_image_header(0);
    
    if (hasRestrictedSegment(header)) {
        NSLog(@"没问题!");
    } else {
        NSLog(@"检测到!!");
        // 退出程序  ,  可以上报 or 记录 ..
        #ifdef __arm64__
            asm volatile(
                         "mov x0,#0\n"
                         "mov x16,#1\n"
                         "svc #0x80\n"
                         );
        #endif
        #ifdef __arm__//32位下
            asm volatile(
                         "mov r0,#0\n"
                         "mov r16,#1\n"
                         "svc #80\n"
                         );
        #endif
    }
}

static bool hasRestrictedSegment(const struct mach_header *mh) {
    const uint32_t cmd_count = mh->ncmds;
    const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(struct macho_header));
    const struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i) {
        switch (cmd->cmd) {
            case LC_SEGMENT_COMMAND:
            {
                const struct macho_segment_command* seg = (struct macho_segment_command*)cmd;
                
                if (strcmp(seg->segname, "__RESTRICT") == 0) {
                    const struct macho_section* const sectionsStart = (struct macho_section*)((char*)seg + sizeof(struct macho_segment_command));
                    const struct macho_section* const sectionsEnd = &sectionsStart[seg->nsects];
                    for (const struct macho_section* sect=sectionsStart; sect < sectionsEnd; ++sect) {
                        if (strcmp(sect->sectname, "__restrict") == 0)
                            return true;
                    }
                }
            }
                break;
        }
        cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
    }
    return false;
}

// 判断是否越狱手机
+ (BOOL)isJailbroken {
    BOOL jailbroken = NO;
    NSString *cydiaPath = @"/Applications/Cydia.app";
    NSString *aptPath = @"/private/var/lib/apt/";
    if ([[NSFileManager defaultManager] fileExistsAtPath:cydiaPath]) {
        jailbroken = YES;
    }
    if ([[NSFileManager defaultManager] fileExistsAtPath:aptPath]) {
        jailbroken = YES;
    }
    return jailbroken;
}

@end
