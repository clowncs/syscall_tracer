import json
import pefile
import idautils
import idc
import idaapi


NT = "nt-per-system.json"
WIN32K = "win32k-per-system.json"
WIN_X64_PATH = "database/windows/x64/"
WIN_X86_PATH = "database/windows/x86/"
MACHINE_TYPES = "database/windows/machine_types/machine_types.json"

def load_json(name):
    file = open(name, "r")
    json_data = json.load(file)
    return json_data

def check_pe_architecture(file_path):
    types = load_json(MACHINE_TYPES)
    pe = pefile.PE(file_path)
    machine = hex(pe.FILE_HEADER.Machine)

    for arch, value in types["x86_32bit"].items():
        if machine == value:
            print(f"[+] Architecture: {arch}")
            return WIN_X86_PATH

    for arch, value in types["x64_64bit"].items():
        if machine == value:
            print(f"[+] Architecture: {arch}")
            return WIN_X64_PATH

    return None
        
def syscall_retrieve(file_path):
    PATH = check_pe_architecture(file_path)
    if PATH is None:
        print("[-] Error: Unsupported architecture")
        exit(1)
    
    if PATH == WIN_X86_PATH:
        NT_SYSCALLS = load_json(PATH + NT)
        WIN32K_SYSCALLS = load_json(PATH + WIN32K)
    else:
        NT_SYSCALLS = load_json(PATH + NT)
        WIN32K_SYSCALLS = load_json(PATH + WIN32K)
    return NT_SYSCALLS, WIN32K_SYSCALLS

def print_syscall_info(EAX_VALUE, head, syscalls_data):
    for windows_version, sp_versions in syscalls_data.items():
        for sp_version, syscalls in sp_versions.items():
            for syscall_name, value in syscalls.items():
                if value == EAX_VALUE:
                    print(f"[+] {head:08X} Windows Version: {windows_version} {sp_version} - "
                          f"syscall: {syscall_name}, {hex(EAX_VALUE)}")


def syscall_tracer_static(NT_SYSCALLS, WIN32K_SYSCALLS):
    EAX_VALUE = None
    breakpoint_list = []    
    for seg in idautils.Segments():
        for head in idautils.Heads(seg, idc.get_segm_end(seg)):
            if idc.is_code(idc.get_full_flags(head)):
                disasm_line = idc.generate_disasm_line(head, 0)
                if disasm_line.startswith("mov     eax,") or disasm_line.startswith("mov     rax,"):
                    type = "mov     eax," if "mov     eax," in disasm_line else "mov     rax,"
                    operands = disasm_line.split(type, 1)[1].split(";")[0].strip()
                    try:
                        parts = operands.split(",")
                        if len(parts) > 1:
                            operands = parts[1].strip()
                    
                        if operands.endswith('h'):  
                            EAX_VALUE = int(operands[:-1], 16) & 0xFFFF
                        elif operands.startswith('0x'): 
                            EAX_VALUE = int(operands, 16) & 0xFFFF
                        else:  
                            EAX_VALUE = int(operands) & 0xFFFF
            
                    except ValueError:
                        pass 

                        
                if "syscall" in disasm_line:    
                    if EAX_VALUE is None:
                        print(f"[-] {head:08X} Error: EAX value can't find with static")
                        breakpoint_list.append(head)
                    
                    print_syscall_info(EAX_VALUE, head, NT_SYSCALLS)
                    print_syscall_info(EAX_VALUE, head, WIN32K_SYSCALLS)
                    EAX_VALUE = None

    return breakpoint_list


def syscall_tracer_dynamic(breakpoint_list):
    return

def main():
    NT_SYSCALLS, WIN32K_SYSCALLS = syscall_retrieve("test_bin/dist-20348.exe")
    break_list = syscall_tracer_static(NT_SYSCALLS, WIN32K_SYSCALLS)
    if break_list != []:
        print(break_list)
        syscall_tracer_dynamic(break_list)
    
    print("[+] Done")


if __name__ == "__main__":
    main()



