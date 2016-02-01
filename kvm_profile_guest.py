#!/usr/bin/env python2.7

dtraceBase = """
#define VCPU_REGS_RBP 5
#define VCPU_REGS_RIP 16

#define BASE_ADDR {base_memory_addr}

"""

dtraceVcpu = """

profile-{profile_interval}
/arg0 && pid == {pid}/
{{
  this->vcpu = (struct kvm_vcpu *)curthread->files->fdt->fd[{vcpu}]->private_data;
  this->kvm = this->vcpu->kvm;
  printf("0x%p\\n", this->vcpu->arch.regs[VCPU_REGS_RIP]);
  this->rbp   = (uintptr_t)this->vcpu->arch.regs[VCPU_REGS_RBP];
}}

"""

dtraceFrame = """

profile-{profile_interval}
/arg0 && pid == {pid} && this->rbp/
{{
  /* This is for frame: {frame_count} */
  this->frame = *(uintptr_t*)copyin(BASE_ADDR + this->rbp + 8, sizeof(uintptr_t));
  this->rbp = *(uintptr_t*)copyin(BASE_ADDR + this->rbp, sizeof(uintptr_t));
  printf("0x%p\\n", this->frame);
}}

"""

dtraceEnd = """

profile-{profile_interval}
/arg0 && pid == {pid}/
{{
  printf("1\\n\\n");
}}

tick-{duration}s
{{
  exit(0);
}}

"""

if __name__ == '__main__':
  import argparse
  import bisect
  import os
  import os.path
  import subprocess
  import sys
  import tempfile

  parser = argparse.ArgumentParser(description="Profile KVM Guests")

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

  args = parser.parse_args()

  vcpu_fds = {}

  for (root, dirs, files) in os.walk(os.path.join('/proc', args.pid)):
    for (fdroot, dirs, files) in os.walk(os.path.join(root, 'fd')):
      for f in files:
        if 'kvm-vcpu' in os.readlink(os.path.join(root, fdroot, f)):
          vcpu_fds[f] = True


  ### TODO serious hack, we *should* be able to use the kvm->memslots or
  ### kvm->mm to deduce this information in the dtrace probe itself, but
  ### inlieu of that lets just find the largest anonymous mapped region
  ### since generally QEMU does a single mmap for the guest's memory.
  mapsizes = {}

  mapfile = os.path.join('/proc', args.pid, 'maps')

  maps = open(mapfile, 'r')
  for line in maps.readlines():
    line = line.strip()
    if 'rw-p 00000000 00:00 0' not in line:
      continue
    parts = line.split()
    addrs = parts[0].split('-')
    start = int(addrs[0], 16)
    end   = int(addrs[1], 16)

    size = end - start
    mapsizes[size] = start

  maps.close()

  sizes = mapsizes.keys()
  sizes.sort()
  base_memory_addr = hex(mapsizes[sizes.pop()])

  symbols = {}
  if args.symbol_file:
    symfile = open(args.symbol_file, 'r')
    for line in symfile.readlines():
      parts = line.strip().split()
      if len(parts) < 3:
        continue
      symbols[int(parts[0], 16)] = parts[2]
  symbol_keys = symbols.keys()
  symbol_keys.sort()

  args = args.__dict__
  args['base_memory_addr'] = base_memory_addr

  script = dtraceBase.format(**args)

  nargs = {}
  nargs.update(**args)

  for vcpu in vcpu_fds:
    nargs['vcpu'] = vcpu
    script += dtraceVcpu.format(**nargs)

    for frame_count in range(1, args['frame_count']):
      nargs['frame_count'] = frame_count
      script += dtraceFrame.format(**nargs)

  script += dtraceEnd.format(**args)

  if args['script_only']:
    print script
    sys.exit(0)

  dscript = tempfile.NamedTemporaryFile(delete=False)
  dscript.write(script)
  dscript.flush()

  dtraceArgs = ['dtrace', '-qC', '-p', args['pid'], '-s', dscript.name]
  child = subprocess.Popen(dtraceArgs, stdout=subprocess.PIPE)
  while child.returncode is None:
    line = child.stdout.readline()

    if line == '':
      break

    if not line.startswith('0x'):
      print line.strip()
      continue

    if len(symbol_keys):
      addr = int(line.strip(), 16)
      loc = bisect.bisect_right(symbol_keys, addr)

      if not loc:
        print line.strip()
        continue

      symkey = symbol_keys[loc - 1]

      print '{}+{:x}'.format(symbols[symkey], addr - symkey)
    else:
      print line.strip()
