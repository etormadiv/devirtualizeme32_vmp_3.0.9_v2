from idc      import *
from idaapi   import *
from idautils import *
import yara

end_addresses = []


def erase_all_breakpoints():
    global end_addresses
    for addr in end_addresses:
        idc.DelBpt(addr)
    end_addresses = []


class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implemented the callback functions """
    image_base = None
    is_vm_exit = False

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        global end_addresses
        instructionsOutput.write("//Process started, pid=%d tid=%d name=%s\n" % (pid, tid, name))
        self.image_base = base
        vm_enter = self.image_base + 0x6BA11
        erase_all_breakpoints()
        end_addresses = get_handler_end_addresses(vm_enter)
        for addr in end_addresses:
            instructionsOutput.write("//Added bp @ %08X\n" % addr)
            idc.AddBpt(addr)

    def dbg_bpt(self, tid, ea):
        global end_addresses
        #print "Break point at 0x%x pid=%d" % (ea, tid)
        eip = ea
        edi = cpu.Edi

        if eip in end_addresses:
            #print "Breakpoint hit:"
            #print " Eip = %08X" % eip
            #print " Edi = %08X" % edi
            if self.is_vm_exit:
                self.is_vm_exit = False
                # One start is okay since we are in a ret instruction

                vm_enter = None

                if is_cpuid_with_vm_enter(Dword(cpu.Esp)):
                    ptr = Dword(cpu.Esp) + 2
                    vm_enter = try_get_vm_enter_address(ptr)
                else:
                    for i in range(1, 100):
                        try:
                            ptr = Dword(cpu.Esp + i * 4)
                            vm_enter = try_get_vm_enter_address(ptr)
                            if vm_enter:
                                break
                        except:
                            pass

                if vm_enter:
                    instructionsOutput.write("//Detected vm_enter after vm_exit\n")
                    erase_all_breakpoints()
                    end_addresses = get_handler_end_addresses(vm_enter)
                    for addr in end_addresses:
                        instructionsOutput.write("//Added bp @ %08X\n" % addr)
                        idc.AddBpt(addr)
                    request_continue_process()
                    run_requests()
                    return 0
                else:
                    instructionsOutput.write("//Failed to detect vm_enter after vm_exit @ %08X\n" % eip)
                    print("[+] INFO: Program probably finished writing instructions...")
                    request_suspend_process()
                    run_requests()
                    return 0

            code_bytes = get_full_handler_code(edi)
            matches = rules.match(data=code_bytes)
            #print "match : " + str(matches)

            if len(matches) == 0:
                instructionsOutput.write("//No yara rule matched handler @ address - image_base = " + hex(edi - self.image_base) + "\n")
                request_suspend_process()
                run_requests()
                return 0

            insn = matches[0].rule[4:]
            instructionsOutput.write(str(getattr(sys.modules[__name__], insn)(cpu.Esi)) + "\n")

            if matches[0].rule == "VMP_Exit":
                self.is_vm_exit = True

            erase_all_breakpoints()
            end_addresses = get_handler_end_addresses(edi)
            #print "End Addresses = " + str(len(end_addresses))
            for addr in end_addresses:
                #print "added bp on @ %08X" % addr
                idc.AddBpt(addr)
            request_continue_process()
            run_requests()
            #print "Requested continue ..."

        return 0


# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
    instructionsOutput.close()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0
instructionsOutput = file("D:\\vmp-program.vmp", "w+", 0)

############################################################
from capstone import *

rules = yara.compile(filepath='D:\\vmp_rules.yar')
disassembler = Cs(CS_ARCH_X86, CS_MODE_32)


def get_jump_instruction_address(disasm):
    for i in disasm:
        if i.mnemonic == "jmp" and i.op_str != "edi":
            return int(i.op_str, 0)
    return None


def is_ending_block(disasm):
    n = 0
    for i in disasm:
        if i.mnemonic == "jmp" and i.op_str == "edi":
            return True
        if i.mnemonic == "push" and i.op_str == "edi" and disasm[n+1].mnemonic == "ret":
            return True
        if i.mnemonic == "pop" and i.op_str == "ebp" and disasm[n+1].mnemonic == "ret":
            return True
        if i.mnemonic == "jmp":
            return False
        n += 1
    return False


def clean_disasm_block(disasm):
    result = []
    n = 0
    for i in disasm:
        if i.mnemonic == "jmp" and i.op_str == "edi":
            result.append(i)
            break
        elif i.mnemonic == "push" and i.op_str == "edi" and disasm[n + 1].mnemonic == "ret":
            result.append(i)
            result.append(disasm[n + 1])
            break
        elif i.mnemonic == "ret":
            result.append(i)
            break
        elif i.mnemonic == "jmp":
            break
        result.append(i)
        n += 1
    return result


def get_full_handler_code(address):
    # type: ([int]) -> str
    global disassembler

    blocks = []
    block_bytes = ""
    reached_end = False

    while not reached_end:
        code = GetManyBytes(address, 100)
        disasm = list(disassembler.disasm(code, address))
        blocks.append(disasm)
        jump_address = get_jump_instruction_address(disasm)
        if jump_address:
            address = jump_address
        else:
            address = disasm[-1].address + disasm[-1].size
        reached_end = is_ending_block(disasm)

    for block in blocks:
        block = clean_disasm_block(block)
        for i in block:
            for j in i.bytes:
                block_bytes += chr(j)

    return block_bytes


def get_handler_end_addresses(address):
    # type: ([int]) -> []
    global disassembler

    address_unmodified = address
    blocks = []
    end_addresses = []
    reached_end = False

    while not reached_end:
        code = GetManyBytes(address, 100)
        disasm = list(disassembler.disasm(code, address))
        blocks.append(disasm)
        jump_address = get_jump_instruction_address(disasm)
        if jump_address:
            address = jump_address
        else:
            address = disasm[-1].address + disasm[-1].size
        reached_end = is_ending_block(disasm)

    for block in blocks:
        block = clean_disasm_block(block)
        n = 0
        for i in block:
            if i.mnemonic == "ja":
                end_addresses.append(int(i.op_str, 0))
            elif (i.mnemonic == "jmp") and (i.op_str == "edi"):
                end_addresses.append(i.address)
            elif (i.mnemonic == "push") and (i.op_str == "edi") and (block[n+1].mnemonic == "ret"):
                end_addresses.append(i.address)
                break
            elif i.mnemonic == "ret":
                end_addresses.append(i.address)
                break
            n += 1

    return end_addresses


def try_get_vm_enter_address(address):
    global disassembler

    code = GetManyBytes(address, 10)
    disasm = list(disassembler.disasm(code, address))
    if len(disasm) == 2:
        if disasm[0].mnemonic == "push" and disasm[1].mnemonic == "call":
            maybe_vm_enter = int(disasm[1].op_str, 0)
            code_bytes = get_full_handler_code(maybe_vm_enter)
            matches = rules.match(data=code_bytes)
            if len(matches) == 1:
                if matches[0].rule == "VMP_Enter":
                    return maybe_vm_enter
    return None


def is_cpuid_with_vm_enter(address):
    global disassembler

    code = GetManyBytes(address, 12)
    disasm = list(disassembler.disasm(code, address))
    if len(disasm) == 3:
        if disasm[0].mnemonic == "cpuid" and disasm[1].mnemonic == "push" and disasm[2].mnemonic == "call":
            maybe_vm_enter = int(disasm[2].op_str, 0)
            code_bytes = get_full_handler_code(maybe_vm_enter)
            matches = rules.match(data=code_bytes)
            if len(matches) == 1:
                if matches[0].rule == "VMP_Enter":
                    return True
    return False

#Handlers


def neg_byte(n):
    return -n & 0xFF


def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n


def ror_byte(value, n):
    return ((value >> n) | (value << 8 - n)) & 0xFF


def rol_byte(value, n):
    return ((value << n) | (value >> 8 - n)) & 0xFF


def ror_word(value, n):
    return ((value >> n) | (value << 16 - n)) & 0xFFFF


def bswap_dword(dword):
    return struct.unpack("<I", struct.pack(">I", dword))[0]


def decrypt_byte(byte):
    byte = (byte ^ cpu.Bl) & 0xFF
    byte = (byte + 1     ) & 0xFF
    byte = (byte ^ 0x48  ) & 0xFF
    byte = neg_byte(byte)
    byte = (byte + 1     ) & 0xFF
    byte = ror_byte(byte, 1)
    byte = (byte + 0x65  ) & 0xFF
    return byte


def decrypt_byte_2(byte):
    byte = (byte ^ cpu.Bl) & 0xFF
    byte = (byte - 1     ) & 0xFF
    byte = (~byte        ) & 0xFF
    byte = ror_byte(byte, 1)
    byte = (byte - 1     ) & 0xFF
    return byte


def decrypt_imm32(dword):
    dword = (dword ^ cpu.Ebx    ) & 0xFFFFFFFF
    dword = bswap_dword(dword   ) & 0xFFFFFFFF
    dword = (dword ^ 0x5ED40265 ) & 0xFFFFFFFF
    dword = (dword - 0x289C020D ) & 0xFFFFFFFF
    dword = (dword ^ 0x66CA52D1 ) & 0xFFFFFFFF
    return dword


def decrypt_imm16(word):
    word = (word ^ cpu.Bx     ) & 0xFFFF
    word = (~word             ) & 0xFFFF
    word = (word + 0x7F84     ) & 0xFFFF
    word = ror_word(word, 1)
    word = (word - 0x77D5     ) & 0xFFFF
    return word


def decrypt_imm8(byte):
    byte = (byte ^ cpu.Bl  ) & 0xFF
    byte = neg_byte(byte   ) & 0xFF
    byte = (byte - 1       ) & 0xFF
    byte = neg_byte(byte   ) & 0xFF
    byte = (~byte          ) & 0xFF
    byte = (byte + 0x0A    ) & 0xFF
    byte = rol_byte(byte, 1) & 0xFF
    byte = (byte ^ 3       ) & 0xFF
    byte = rol_byte(byte, 1) & 0xFF
    byte = (byte + 0x4D    ) & 0xFF
    byte = ror_byte(byte, 1) & 0xFF
    byte = (byte ^ 0x6F    ) & 0xFF
    byte = (byte + 1       ) & 0xFF
    return byte


def get_instruction_size(name):
    raise NotImplementedError


class Enter:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class PopReg32:
    # Data values
    reg_id = None
    # Semantics
    stack_change = 4
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        byte = ord(GetManyBytes(self.bytecode_address - 1, 1)[0])
        self.reg_id = decrypt_byte(byte)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.reg_id)


class PopReg16:
    # Data values
    reg_id = None
    # Semantics
    stack_change = 2
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        byte = ord(GetManyBytes(self.bytecode_address - 1, 1)[0])
        self.reg_id = decrypt_byte_2(byte)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.reg_id)


class PushReg32:
    # Data values
    reg_id = None
    # Semantics
    stack_change = -4
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        byte = ord(GetManyBytes(self.bytecode_address - 1, 1)[0])
        self.reg_id = decrypt_byte(byte)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.reg_id)


class PushReg16:
    # Data values
    reg_id = None
    # Semantics
    stack_change = -2
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        byte = ord(GetManyBytes(self.bytecode_address - 1, 1)[0])
        self.reg_id = decrypt_byte_2(byte)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.reg_id)


class PushEsp:
    # Data values

    # Semantics
    stack_change = -4
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class PopEsp:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class PushImm32:
    # Data values
    value = None
    # Semantics
    stack_change = -4
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        dword, = struct.unpack("<I", GetManyBytes(self.bytecode_address - 4, 4))
        self.value = decrypt_imm32(dword)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.value)


class PushImm16:
    # Data values
    value = None
    # Semantics
    stack_change = -2
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        word, = struct.unpack("<H", GetManyBytes(self.bytecode_address - 2, 2))
        self.value = decrypt_imm16(word)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.value)


class PushImm8:
    # Data values
    value = None
    # Semantics
    stack_change = -2
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        byte, = struct.unpack("<B", GetManyBytes(self.bytecode_address - 1, 1))
        self.value = decrypt_imm8(byte)

    def __str__(self):
        return "%08X: %s %X" % (self.bytecode_address, self.__class__.__name__, self.value)


class Add32:
    # Data values

    # Semantics
    stack_change = 0
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Add16:
    # Data values

    # Semantics
    stack_change = 0
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Nand32:
    # Data values

    # Semantics
    stack_change = 0
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Nand16:
    # Data values

    # Semantics
    stack_change = 0
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class DerefMemSs32:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class DerefMemSs16:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class DerefMemSs8:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class SetMemSs32:
    # Data values

    # Semantics
    stack_change = 8
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class DerefMem32:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Exit:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Shr32:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Shl32:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Jump:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class ResetJumpDisplacement:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)


class Mul32:
    # Data values

    # Semantics
    stack_change = None
    size = None

    def __init__(self, bytecode_address):
        self.bytecode_address = bytecode_address
        self.decode_backward()

    def decode_backward(self):
        pass

    def __str__(self):
        return "%08X: %s" % (self.bytecode_address, self.__class__.__name__)