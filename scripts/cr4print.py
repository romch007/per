CR4_FLAGS = {
    0:  "VME",
    1:  "PVI",
    2:  "TSD",
    3:  "DE",
    4:  "PSE",
    5:  "PAE",
    6:  "MCE",
    7:  "PGE",
    8:  "PCE",
    9:  "OSFXSR",
    10: "OSXMMEXCPT",
    11: "UMIP",
    12: "LA57",
    13: "VMXE",
    14: "SMXE",
    16: "FSGSBASE",
    17: "PCIDE",
    18: "OSXSAVE",
    20: "SMEP",
    21: "SMAP",
    22: "PKE",
    23: "CET",
}

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def pretty_print_cr4(cr4):
    print(f"CR4 = 0x{cr4:016x}\n")
    for bit, name in sorted(CR4_FLAGS.items()):
        enabled = bool(cr4 & (1 << bit))
        status = GREEN + "ON" + RESET if enabled else RED + "OFF" + RESET
        print(f"[{bit:02}] {name:<12} : {status}")

pretty_print_cr4(0x00000000000506f8)