//
//  AntiDebugCode.m
//  MyPtraceHeader
//
//  Created by cib on 2023/4/21.
//
// 参考链接：https://juejin.cn/post/6844904143979560974

#import "AntiDebugCode.h"
#import <sys/sysctl.h>
#import "PtraceHeader.h"
#import <dlfcn.h>

// 一定要在最前面
@implementation AntiDebugCode

// 检测调试
BOOL isDebugger(void){
    int name[4];              // 里面放字节码。查询的信息
    name[0] = CTL_KERN;        // 内核查询
    name[1] = KERN_PROC;       // 查询进程
    name[2] = KERN_PROC_PID;    // 传递的参数是进程的ID
    name[3] = getpid();        // PID的值
    
    struct kinfo_proc info;                     // 接受查询结果的结构体
    size_t info_size = sizeof(info);            // 结构体的大小
    int length = sizeof(name)/sizeof(*name);    // name大小，就是4
    if(sysctl(name, length, &info, &info_size, 0, 0)){
        NSLog(@"查询失败");
        return NO;
    }
    
    // 看info.kp_proc.p_flag 的第12位。如果为1，表示调试状态。
    // (info.kp_proc.p_flag & P_TRACED)
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

static dispatch_source_t timer;
void debugCheck(void) {
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(0, 0));
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 5.0 * NSEC_PER_SEC, 0.0 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (isDebugger()) {
            NSLog(@"调试状态！！");
            entry();
        }else{
            NSLog(@"正常！");
        }
    });
    dispatch_resume(timer);
}

+(void)load {
    debugCheck();
    // 开启反调试
    /**
     方法1
     arg1: ptrace要做的事情: PT_DENY_ATTACH 表示要控制的是当前进程不允许被附加
     arg2: 要操作进程的PID , 0就代表自己
     arg3: 地址 取决于第一个参数要做的处理不同传递不同
     arg4: 数据 取决于第一个参数要做的处理不同传递不同
     */
//    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    
    /**
    方法2
    参数一：参数是函数编号
    其它参数：给参数一的函数提供参数
    */
//    syscall(SYS_ptrace,PT_DENY_ATTACH,0,0);

    // 方法三，使用ptrace汇编
    entry();
}

__attribute__((constructor)) void entry(void) {
#ifdef DEBUG
// debug
#else
    // volatile代表不优化此汇编代码
    #ifdef __arm__
    __asm__ volatile(
            "mov r0,#0x1F\n"
            "mov r1,#0x0\n"
            "mov r2,#0x0\n"
            "mov r12,#0x1A\n"
            "svc #0x80");
    #endif
    #ifdef __arm64__
    __asm__ volatile(
            "mov X0, #0x1A\n"
            "mov X1, #0x1F\n"
            "mov X2, #0x0\n"
            "mov X3, #0x0\n"
            "mov X16,#0x0\n"
            "svc #0x80");
    #endif
#endif
}

#pragma mark - ptrace调用
void ptrace_handle(void) {
    //使用一个char数组拼接一个ptrace字符串 （此拼接方式可以让逆向的人在使用工具查看汇编时无法直接看到此字符串）
    unsigned char funcName[] = {
        ('q' ^ 'p'),
        ('q' ^ 't'),
        ('q' ^ 'r'),
        ('q' ^ 'a'),
        ('q' ^ 'c'),
        ('q' ^ 'e'),
        ('q' ^ '\0'),
    };
    unsigned char * p = funcName;
    //再次异或之后恢复原本的值
    while (((*p) ^= 'q') != '\0') p++;

    //通过dlopen拿到句柄
    void * handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY);
    //定义函数指针
    int (*ptrace_p)(int _request, pid_t _pid, caddr_t _addr, int _data);
    //如果拿到句柄
    if (handle) {
        //通过dlsym拿到函数指针
        ptrace_p = dlsym(handle, (const char *)funcName);
        //如果拿到函数指针
        if (ptrace_p) {
            //调用所需函数
            ptrace_p(PT_DENY_ATTACH, 0, 0, 0 );
        }
    }
}

@end
