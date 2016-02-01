## Profiling KVM Guests with DTrace

Given a Linux environment that has DTrace and KVM you can walk arbitrary VCPU's
for their stack traces and print them.

```
./kvm_profile_guest.py --help
usage: kvm_profile_guest.py [-h] --pid PID [--vcpu_count VCPU_COUNT]
                            [--symbol_file SYMBOL_FILE]
                            [--frame_count FRAME_COUNT] [--duration DURATION]
                            [--profile_interval PROFILE_INTERVAL]
                            [--script_only]

Profile KVM Guests

optional arguments:
  -h, --help            show this help message and exit
  --pid PID             PID of QEMU process to profile
  --vcpu_count VCPU_COUNT
                        The number of VCPUs to profile
  --symbol_file SYMBOL_FILE
                        Optional symbol file for name resolution
  --frame_count FRAME_COUNT
                        Number of frames to walk
  --duration DURATION   Duration to profile
  --profile_interval PROFILE_INTERVAL
                        Interval to query VCPUs
  --script_only         Only print DTrace script
```
