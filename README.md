## Profiling KVM Guests with DTrace

Given a Linux environment that has DTrace and KVM you can walk arbitrary VCPU's
for their stack traces and print them. Tested on OracleLinux 7.2.

```
usage: vm_profile_guest.py [-h] --pid PID [--symbol_file SYMBOL_FILE]
                           [--frame_count FRAME_COUNT] [--duration DURATION]
                           [--profile_interval PROFILE_INTERVAL]
                           [--script_only] [--base_address BASE_ADDRESS]

Profile VM Guests

optional arguments:
  -h, --help            show this help message and exit
  --pid PID             PID of QEMU process to profile
  --symbol_file SYMBOL_FILE
                        Optional symbol file for name resolution
  --frame_count FRAME_COUNT
                        Number of frames to walk
  --duration DURATION   Duration to profile
  --profile_interval PROFILE_INTERVAL
                        Interval to query VCPUs
  --script_only         Only print DTrace script
  --base_address BASE_ADDRESS
                        base address value
```

Output:

```
cpu_intr_ack+a
ipintr+88f
sithread+77
threadbouncer+50
bmk_cpu_sched_bouncer+b
1

bmk_platform_cpu_block+5a
schedule+89
bmk_sched_block+23
wait.isra.0+61
rumpuser_cv_wait+3c
sithread+88
threadbouncer+50
bmk_cpu_sched_bouncer+b
1

cpu_intr_ack+a
threadbouncer+50
bmk_cpu_sched_bouncer+b
1

bmk_platform_cpu_block+5a
schedule+89
bmk_sched_block+23
wait.isra.0+61
rumpuser_cv_wait+3c
docvwait+7c
rumpns_cv_timedwait_sig+45
rumpns_kevent1+318
rumpns_sys___kevent50+33
rump_syscall+78
_sys___kevent50+4e
__kevent50+30
ngx_kqueue_process_events+93
ngx_process_events_and_timers+9d
ngx_single_process_cycle+74
rumprun_main1+a4d
mainbouncer+4c
pthread__create_tramp+6e
bmk_cpu_sched_bouncer+b
1
```
