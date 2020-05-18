#!/usr/bin/env python


class Linux:
    dtraceBase = """
#define VCPU_REGS_RBP 5
#define VCPU_REGS_RIP 16

#define BASE_ADDR {base_memory_addr}
    """

    dtraceVcpu = """
profile-{profile_interval}
/pid == {pid}/
{{
    this->vcpu_id = {vcpu};
    this->vcpu = (struct kvm_vcpu *)curthread->files->fdt->fd[{vcpu}]->private_data;
    this->kvm = this->vcpu->kvm;
    printf("0x%p\\n", this->vcpu->arch.regs[VCPU_REGS_RIP]);
    this->rbp   = (uintptr_t)this->vcpu->arch.regs[VCPU_REGS_RBP];
    this->frame_id = 0;
}}
    """

    def __init__(self, pid):
        self.pid = pid

    def dtrace_base(self):
        return Linux.dtraceBase

    def get_vcpus(self):
        vcpu_fds = {}

        for (root, dirs, files) in os.walk(os.path.join('/proc', self.pid)):
            for (fdroot, dirs, files) in os.walk(os.path.join(root, 'fd')):
                for f in files:
                    if 'kvm-vcpu' in os.readlink(os.path.join(root, fdroot, f)):
                        vcpu_fds[f] = True

    def find_base_address(self):
        # TODO serious hack, we *should* be able to use the kvm->memslots or
        # kvm->mm to deduce this information in the dtrace probe itself, but
        # inlieu of that lets just find the largest anonymous mapped region
        # since generally QEMU does a single mmap for the guest's memory.
        mapsizes = {}

        mapfile = os.path.join('/proc', self.pid, 'maps')

        with open(mapfile, 'r') as maps:
            for line in maps.readlines():
                line = line.strip()
                if 'rw-p 00000000 00:00 0' not in line:
                    continue
                parts = line.split()
                addrs = parts[0].split('-')
                start = int(addrs[0], 16)
                end = int(addrs[1], 16)

                size = end - start
                mapsizes[size] = start

        sizes = list(mapsizes.keys())
        sizes.sort()
        base_memory_addr = hex(mapsizes[sizes.pop()])
        return base_memory_addr

# current impl mojave
# catalina, offset to regs in cpu_state seems to now be 0x780
# offset to cpu_state appears to be 0x30, which would be the same
# offset to vcpu set seems to still be 0x40


class Darwin:
    dtraceBase_common = """
#define HV_X86_RIP 0
#define HV_X86_RBP 9
#define BASE_ADDR {base_memory_addr}
"""

    dtraceBase_mojave = """
struct cpu_state_mojave {{
    char pad[0x340];
    uint64_t reg[0x32];
}};

struct hv_vmx_vcpu_t {{
    uintptr_t pad_ptrs[0x5];
    struct cpu_state_mojave *state;
}};

struct vcpu_set_mojave {{
    struct hv_vmx_vcpu_t* vcpus[32];
}};

struct hv_vmx_vm_t {{
    uintptr_t pad_ptrs[0x6];
    struct vcpu_set_mojave *vcpu_set;
}};
"""

    dtraceBase_catalina = """
struct cpu_state_catalina {{
    char pad[0x780];
    uint64_t reg[0x32];
}};


struct hv_vmx_vcpu_t {{
    uintptr_t pad_ptrs[0x6];
    struct cpu_state_catalina *state;
}};


struct vcpu_set_catalina {{
    struct hv_vmx_vcpu_t* vcpus[32];
}};


struct hv_vmx_vm_t {{
    uintptr_t pad_ptrs[0x8];
    struct vcpu_set_catalina *vcpu_set;
}};
    """

    dtraceVcpu = """
profile-{profile_interval}
/pid == {pid}/
{{
    this->vcpu_id = {vcpu};
    this->vcpu = (struct hv_vmx_vcpu_t*){vcpu};
    this->state = this->vcpu->state;

    this->rbp = this->state->reg[HV_X86_RBP];
    printf("thread_id: %d\\t0x%p\\n", tid, this->state->reg[HV_X86_RIP]);

    this->frame_id = 0;
}}
    """

    dtraceVcpu_count = """
profile-997
/pid == {pid}/
{{
    this->task = (struct hv_vmx_vm_t*)curthread->task->hv_task_target;
    this->vcpu_set = this->task->vcpu_set;
    printf("0x%p\\n", this->vcpu_set->vcpus[0]);
    printf("0x%p\\n", this->vcpu_set->vcpus[1]);
    printf("0x%p\\n", this->vcpu_set->vcpus[2]);
    printf("0x%p\\n", this->vcpu_set->vcpus[3]);
    printf("0x%p\\n", this->vcpu_set->vcpus[4]);
    printf("0x%p\\n", this->vcpu_set->vcpus[5]);
    printf("0x%p\\n", this->vcpu_set->vcpus[6]);
    printf("0x%p\\n", this->vcpu_set->vcpus[7]);
    printf("0x%p\\n", this->vcpu_set->vcpus[8]);
    printf("0x%p\\n", this->vcpu_set->vcpus[9]);
    printf("0x%p\\n", this->vcpu_set->vcpus[10]);
    printf("0x%p\\n", this->vcpu_set->vcpus[11]);
    printf("0x%p\\n", this->vcpu_set->vcpus[12]);
    printf("0x%p\\n", this->vcpu_set->vcpus[13]);
    printf("0x%p\\n", this->vcpu_set->vcpus[14]);
    printf("0x%p\\n", this->vcpu_set->vcpus[15]);
    printf("0x%p\\n", this->vcpu_set->vcpus[16]);
    printf("0x%p\\n", this->vcpu_set->vcpus[17]);
    printf("0x%p\\n", this->vcpu_set->vcpus[18]);
    printf("0x%p\\n", this->vcpu_set->vcpus[19]);
    printf("0x%p\\n", this->vcpu_set->vcpus[20]);
    printf("0x%p\\n", this->vcpu_set->vcpus[21]);
    printf("0x%p\\n", this->vcpu_set->vcpus[22]);
    printf("0x%p\\n", this->vcpu_set->vcpus[23]);
    printf("0x%p\\n", this->vcpu_set->vcpus[24]);
    printf("0x%p\\n", this->vcpu_set->vcpus[25]);
    printf("0x%p\\n", this->vcpu_set->vcpus[26]);
    printf("0x%p\\n", this->vcpu_set->vcpus[27]);
    printf("0x%p\\n", this->vcpu_set->vcpus[28]);
    printf("0x%p\\n", this->vcpu_set->vcpus[29]);
    printf("0x%p\\n", this->vcpu_set->vcpus[30]);
    printf("0x%p\\n", this->vcpu_set->vcpus[31]);
    exit(0);
}}
    """

    def __init__(self, pid):
        self.pid = pid

    def dtrace_base(self):
        releaseNum = platform.mac_ver()[0]
        if releaseNum.startswith('10.15'):
            return Darwin.dtraceBase_common + Darwin.dtraceBase_catalina
        else:
            return Darwin.dtraceBase_common + Darwin.dtraceBase_mojave

    def find_base_address(self):
        import re
        # VM_ALLOCATE            0000000117de6000-000000011fde6000 [128.0M 128.0M 128.0M     0K] rw-/rwx SM=ALI
        VM_REG = r"^VM_ALLOCATE\s+([a-f0-9]+)-([a-f0-9]+)\s+\[([0-9.MKG]+)\s+([0-9.MKG]+)\s+([0-9.MKG]+)\s+([0-9.MKG]+)\]\s+rw-/rwx\s+SM=ALI"

        mapsizes = {}

        child = subprocess.Popen(['vmmap', self.pid], stdout=subprocess.PIPE)
        while child.returncode is None:
            line = child.stdout.readline()

            if line == '':
                break

            line = line.strip()

            m = re.search(VM_REG, line)

            if not m:
                continue

            start_address = int(m.group(1), 16)
            end_address = int(m.group(2), 16)
            size = end_address - start_address

            mapsizes[size] = start_address
        sizes = list(mapsizes.keys())
        sizes.sort()
        base_memory_addr = hex(mapsizes[sizes.pop()])
        return base_memory_addr

    def get_vcpus(self):
        script = self.dtrace_base()
        script += Darwin.dtraceVcpu_count
        script = script.format(pid=self.pid, base_memory_addr=0)
        dscript = tempfile.NamedTemporaryFile()
        dscript.write(script)
        dscript.flush()
        dtraceArgs = ['dtrace', '-qC', '-p', self.pid, '-s', dscript.name]
        child = subprocess.Popen(dtraceArgs, stdout=subprocess.PIPE)
        cpus = []
        for line in child.stdout.readlines():
            line = line.strip()
            if line == '':
                continue
            if not line.startswith('0x'):
                continue
            if line != '0x0':
                cpus.append(line)
        return cpus


dtraceFrame = """
profile-{profile_interval}
/pid == {pid} && this->rbp && this->vcpu_id == {vcpu} && this->frame_id == {frame_count}/
{{
  /* This is for vcpu: {vcpu} frame: {frame_count} */
  this->frame = *(uintptr_t*)copyin(BASE_ADDR + this->rbp + 8, sizeof(uintptr_t));
  this->rbp = *(uintptr_t*)copyin(BASE_ADDR + this->rbp, sizeof(uintptr_t));
  printf("thread_id: %d\\t0x%p\\n", tid, this->frame);
  this->frame_id += 1;
}}
"""

dtraceEnd = """
profile-{profile_interval}
/pid == {pid} && this->vcpu_id == {vcpu}/
{{
  printf("thread_id: %d\\t1\\n\\n", tid);
}}

tick-{duration}s
{{
  exit(0);
}}
"""


def process_line(stacks, symbol_keys, symbols, line):
    line = line.strip()

    if line == '':
        return

    if not line.startswith('thread_id:'):
        return

    parts = line.split()

    thread_id = parts[1]

    line = parts[2]

    if thread_id not in stacks:
        stacks[thread_id] = []

    stack = stacks[thread_id]

    if not line.startswith('0x'):
        print(('\n'.join(stack)))
        print('1')
        print('')
        stacks[thread_id] = []
        return

    addr = int(line, 16)

    if len(symbol_keys):
        loc = bisect.bisect_right(symbol_keys, addr)

        if not loc:
            print(line)

        symkey = symbol_keys[loc - 1]

        symname = symbols[symkey]
        stack.append("{}+{:x}".format(symbols[symkey], addr - symkey))
    else:
        stack.append("{}".format(line))


if __name__ == '__main__':
    import argparse
    import bisect
    import os
    import os.path
    import platform
    import subprocess
    import sys
    import tempfile

    parser = argparse.ArgumentParser(description="Profile VM Guests")

    parser.add_argument('--pid', help="PID of QEMU process to profile",
                        required=True)
    parser.add_argument('--vcpu_count', help="The number of VCPUs to profile",
                        default=1)
    parser.add_argument('--symbol_file',
                        help="Optional symbol file for name resolution")
    parser.add_argument('--frame_count', help="Number of frames to walk",
                        default=10, type=int)
    parser.add_argument('--duration', help="Duration to profile", default=10)
    parser.add_argument('--profile_interval', help="Interval to query VCPUs",
                        default=997)
    parser.add_argument('--script_only', help="Only print DTrace script",
                        action='store_true', default=False)
    parser.add_argument(
        '--base_address', help="base address value", default=None)

    args = parser.parse_args()

    plat = platform.system()

    base_system = None
    if plat == 'Darwin':
        base_system = Darwin
    elif plat == 'Linux':
        base_system = Linux

    base_system = base_system(args.pid)

    if not args.base_address:
        base_memory_addr = base_system.find_base_address()
    else:
        base_memory_addr = args.base_address

    symbols = {}
    if args.symbol_file:
        symfile = open(args.symbol_file, 'r')
        for line in symfile.readlines():
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            symbols[int(parts[0], 16)] = parts[2]
    symbol_keys = list(symbols.keys())
    symbol_keys.sort()

    args = args.__dict__

    args['base_memory_addr'] = base_memory_addr

    script = base_system.dtrace_base().format(**args)

    nargs = {}
    nargs.update(**args)

    for vcpu in base_system.get_vcpus():
        nargs['vcpu'] = vcpu
        script += base_system.dtraceVcpu.format(**nargs)

        for frame_count in range(0, args['frame_count']):
            nargs['frame_count'] = frame_count
            script += dtraceFrame.format(**nargs)

        script += dtraceEnd.format(**nargs)

    if args['script_only']:
        print(script)
        sys.exit(0)

    dscript = tempfile.NamedTemporaryFile()
    dscript.write(script)
    dscript.flush()

    dtraceArgs = ['dtrace', '-qC', '-p', args['pid'], '-s', dscript.name]
    child = subprocess.Popen(dtraceArgs, stdout=subprocess.PIPE)

    stacks = {}

    while child.returncode is None:
        line = child.stdout.readline()

        if line == '':
            break

        process_line(stacks, symbol_keys, symbols, line)

    for line in child.stdout.readlines():
        process_line(stacks, symbol_keys, symbols, line)

    for tid, stack in list(stacks.items()):
        if len(stack):
            print(('\n'.join(stack)))
            print('1')
            print('')
