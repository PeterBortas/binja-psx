import binaryninja as bn
from binaryninja.log import log_error, log_debug, log_info, log_alert, log_warn, log_to_stderr, log_to_stdout

def psx_get_type(calladdr, callnr):
    psx_bios_calls = {
        0xa0: {
            0x00: ["open",    "int open(char *name, int mode)"],
            0x01: ["lseek",   "int lseek(int fd, int offset, int mode)"],
            0x02: ["read",    "int read(int fd , char *buf , int nbytes)"],
            0x03: ["write",   "int write(int fd , char *buf , int nbytes)"],
            0x04: ["close",   "int close(int fd)"],
            0x05: ["ioctl",   "int ioctl(int fd, int request, ...)"],
            0x06: ["exit",    "void exit(int error)"],
            0x07: False,       # Unknown
            0x08: ["getc",    "int getc()"],
            0x09: ["putc",    "int putc(int c)"],
            0x0a: ["todigit", "void todigit()"], # FIXME: needs type
            0x0b: ["atof",    "double atof(const char *nptr)"],
            0x0c: ["strtoul"  "unsigned long strtoul(const char *nptr, char **endptr, int base)"],
            0x0d: ["strtol",  "long strtol(const char *nptr, char **endptr, int base)"],
            0x0e: ["abs",     "int abs(int j)"],
            0x0f: ["labs",    "long labs(long j)"],
            0x10: ["atoi",    "int atoi(const char *nptr)"],
            0x11: ["atol",    "long atol(const char *nptr)"],
            0x13: ["setjmp",  "int setjmp(jmp_buf p)"],
            0x14: ["longjmp", "int longjmp(jmp_buf p, int val)"],
            0x15: ["strcat",  "char *strcat(char *dest, const char *src)"],
            0x16: ["strncat", "char *strncat(char *dest, const char *src, size_t n)"],
            0x17: ["strcmp",  "int strcmp(const char *s1, const char *s2)"],
            0x18: ["strncmp", "int strncmp(const char *s1, const char *s2, size_t n)"],
            0x19: ["strcpy",  "char *strcpy(char *dest, const char *src)"],
            0x1a: ["strncpy", "int strncpy(const char *dest, const char *src, size_t n) "],
            0x1b: ["strlen",  "size_t strlen(const char *s)"],
            0x39: ["InitHeap", "void InitHeap(unsigned int *heap, unsigned int size)"],
            0x3f: ["printf",  "int printf(const char *format, ...)"],
            # Really: Exec(struct EXEC *exec, ---
            0x43: ["Exec",    "long Exec(uint32_t *exec, long argc, char *argv)"],
            0x44: ["FlushCache", "void FlushCache()"],
            0x47: ["mem2vram", "void mem2vram(int x, int y, int w, int h, long *data)"],
            0x48: ["SendGPU",     "void SendGPU(int status)"],
            0x49: ["GPU_cw",      "void GPU_cw(uint32_t cw)"],
            0x70: ["_bu_init",    "void _bu_init(void)"],
            0x72: ["_96_remove",  "void _96_remove()"],
            0x9f: ["SetMem",      "void SetMem(unsigned long memsize)"],
            0xa1: ["SystemError", "void SystemError()"], # FIXME type
            0xa2: ["EnqueueCdIntr", "EnqueueCdIntr"], # FIXME type
            0xab: ["_card_info",  "long _card_info(long chan)"],
            0xac: ["_card_load",  "long _card_load(long chan)"],
            0xad: ["_card_auto",  "long _card_auto(long val)"],
        },
        0xb0: {
            0x00: ["SysMalloc", "void SysMalloc()"], # FIXME type
            0x02: ["SetRcnt", "int SetRcnt()"],
            0x04: ["StartRcnt", "bool StartRcnt(int counter)"],
            0x07: ["DeliverEvent", "void DeliverEvent(int cause_desc, int event_class)"], # FIXME type
            0x08: ["OpenEvent", "int OpenEvent(int event_class, int event_spec, int event_mode, uint32_t *func)"], # FIXME type
            0x0a: ["WaitEvent", "int WaitEvent(int event)"], #FIXME type
            0x0b: ["TestEvent", "bool TestEvent(int event)"],
            0x0c: ["EnableEvent", "bool EnableEvent(int event)"],
            0x0d: ["DisableEvent", "bool DisableEvent(int event)"],
            0x12: ["InitPAD", "int InitPAD(char *buf1,int len1,char *buf2,int len2)"],
            0x13: ["StartPAD", "void StartPAD()"], #FIXME type
            0x14: ["StopPAD",  "void StopPAD()"],  #FIXME type
            0x15: ["PAD_init", "int PAD_init(int unknown1, int *unknown2)"], # FIXME name
            0x16: ["PAD_dr",   "int PAD_dr()"],
            0x17: ["ReturnFromException", "void ReturnFromException()"],
            0x18: ["ResetEntryInt", "void ResetEntryInt()"],
            0x19: ["HookEntryInt", "int HookEntryInt(uint32_t *hook)"], # FIXME name, type

            # FIXME: B0 versions of A0. Don't remember the differance
            # or if they have other names. Just adding "2" for now.
            0x32: ["open2",    "int open(char *name, int mode)"],
            0x33: ["lseek2",   "int lseek(int fd, int offset, int mode)"],
            0x34: ["read2",    "int read(int fd , char *buf , int nbytes)"],
            0x35: ["write2",   "int write(int fd , char *buf , int nbytes)"],
            0x36: ["close2",   "int close(int fd)"],
            0x37: ["ioctl2",   "int ioctl(int fd, int request, ...)"],
            0x38: ["exit2",    "void exit(int error)"],
            0x39: False,        # Unknown
            0x3a: ["getc2",    "int getc()"],
            0x3b: ["putc2",    "int putc(int c)"],
            0x3c: ["getchar2", "int getchar(void)"],
            0x3d: ["putchar2",  "int putchar(char c)"],
            0x3e: ["puts2",     "int putc(int c)"],
            
            0x42: ["firstfile", "int firstfile(string unknown1, int unknown2)"], #FIXME names
            0x43: ["nextfile",   "int nextfile(int unknown)"],  #FIXME names
            0x4a: ["InitCard",   "void InitCard(int unknown)"], #FIXME names
            0x4b: ["StartCard",  "void StartCard()"],
            0x56: ["GetC0Table", "int GetC0Table()"],
            0x57: ["GetB0Table", "int GetB0Table()"],
            0x5b: ["ChangeClearPAD", "void ChangeClearPAD(int irqflag)"],
        },
        0xc0: {
            0x07: ["InstallExceptionHandlers", "void InstallExceptionHandlers()"], # FIXME type
            0x08: ["SysInitMemory", "void SysInitMemory()"],     # FIXME type
            0x0a: ["ChangeClearRCnt", "void ChangeClearRCnt()"], # FIXME type
            0x0c: ["InitDefInt", "void InitDefInt()"],           # FIXME type
        },
        0: {
            0: ["Exception", "void Exception()"],            # FIXME: type
            1: ["Exception", "bool EnterCriticalSection()"], # FIXME: type
            2: ["ExitCriticalSection", "void ExitCriticalSection()"],
        }
    }

#    log_info("Looking up %s call %s" % (format(calladdr, '#06x'),
#                                        format(callnr, '#06x')))
    res = psx_bios_calls[calladdr][callnr]
    return res

def safe_psx_set_type(view, f, calladdr, callnr):
    try:
        type = psx_get_type(calladdr, callnr)
    except:
        if calladdr:
            log_error("failed to lookup %s call %s" %
                      (format(calladdr, '#5x'),
                       format(callnr, '#05x')))
        else:
            log_error("failed to lookup syscall %s" % callnr)
    if type:
        new_name = "PSX_"+ type[0]
        f.name = new_name
        i = 0
        # TODO: Avoid touching user defined functions
        while f.name != new_name:
            log_warn("Unable to change name to %r, duplicate? Trying numbered alias" % new_name)
            new_name = "PSX_"+ type[0] +"_copy_"+ str(i)
            f.name = new_name
            f.set_user_type(view.parse_type_string(type[1])[0])
    else:
        if calladdr:
            log_warn("Unknown %s call: %s" %
                     (format(calladdr, '#5x'),
                      format(callnr, '#05x')))
        else:
            log_warn("Unknown syscall %s" % callnr)

# This is a mess but does what I need
def run_plugin(view):
    for f in view.functions:
        if len(f.medium_level_il) == 2:
            tok0 = f.medium_level_il[0].tokens
	    if str(tok0[0]) == '$t1' and str(tok0[1]) == ' = ':
	        callnr = int(str(tok0[2]), 16)
	        tok1 = f.medium_level_il[1].tokens
                if str(tok1[0]) == 'jump(' and str(tok1[2]) == ')':
	            calladdr = int(str(tok1[1]), 16)
                    safe_psx_set_type(view, f, calladdr, callnr)
            # TODO: Only verified for syscall(2) stub
	    if str(tok0[0]) == '$v0' and str(tok0[1]) == ' = ' and str(tok0[2]) == 'syscall':
	        callnr = int(str(tok0[4]))
                safe_psx_set_type(view, f, 0, callnr)
