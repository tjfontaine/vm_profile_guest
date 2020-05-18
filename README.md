# Profiling VM Guests with DTrace

Given a Linux or macOS environment that has DTrace and `KVM` or
`Hypervisor.framework` respectively, you can print stack traces for their
vCPU's.  Tested with QEMU on macOS Mojave and Catalina (`-accel hvf`), as well
as Oracle Linux 7 with UEK5 (`-enable-kvm`). If you supply a symbol file in the
format used by `nm`, addresses (if found) will be resolved into their
appropriate symbol name. The output can be used with tools for producing Flame
Graphs.

## Usage

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

## Output

Here is the output of a [rumpkernel](https://github.com/rumpkernel/rumprun)
running the [nginx package](https://github.com/rumpkernel/rumprun-packages):

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

The format is ready to be used with tools for producing [Flame
Graphs](http://www.brendangregg.com/flamegraphs.html) such as can be found in
Brendan Gregg's [tools](https://github.com/brendangregg/FlameGraph).

## Caveats and Assumptions

### Frame Pointers

In order to walk the stack this tool assumes the guest has preserved frame
pointers. That is to say it's been compiled with `-fno-omit-frame-pointer`.
This is crucial, if `RBP` isn't in fact the base pointer, you will not get
sensical information from this tool. Suffice it to say, compilers no longer
preserve frame pointers by default, so you'll need to make sure you have this
covered.

### Address Spaces

Normally for DTrace one only has to think about `kernel` and `user` address
spaces, and to remember that DTrace is operating in the `kernel` and so you may
need to `copyin` to the kernel addresse space from `user` space.

But when profiling a Virtual Machine one must also be aware of the addressing
within that guest machine.

The demo above demonstrates using the tool against a Unikernel running inside
the VM. This greatly simplifies the effort needed to produce a stack trace
because we can assume the unikernel has a single unified address layout. That
is to say, the guest doesn't have its own notion of `kernel` and `user` address
spaces.

Keep in mind that DTrace has strict requirements regarding loops and branching,
so if you want to be able to profile a full stack from a guest running a more
complicated (useful?) operating system, you'll need to be able to resolve
"easily" `guest-user` space addresses into `host-user` addresses such that they
can be `copyin`'d and the stack can be walked.

Also, DTrace requires the memory for the guest to be paged in for the `copyin`
to work, it's possible that given your `VMM` this may not be the case. If the
script is failing with multiple errors about not being able to `copyin` an
address, and you're using `qemu` try using the flag `-mem-prealloc` (though
this could also be representative of missing frame pointers).

### macOS

For this tool to work you must have SIP configured to allow _both_ DTrace *and*
Debugging (because we want DTrace to _attach_ to the process). As such, that
means you need to boot into restore mode and from a terminal issue the
following command: `csrutil enable --without dtrace --without debug`

The ability to trace a guest running on `Hypervisor.framework` is (putting it
lightly) very fragile, perhaps even more fragile than the notion of walking a
stack of a running virtual machine. While there is enough `CTF` in Apple's
kernel to identify `hv_thread_target` and `hv_task_target`, they are merely
mapped to `void*` instead of their more concrete types. This is to be expected,
as they're largely an implementation detail and no rational person should be
depending on the layout of any of the related structures. But yet, here we are.

To that end, through a combination of reverse engineering `AppleHV.kext`,
DTrace's `tracemem`, and a version of [Philipp Oppermann's Rust
OS](https://github.com/phil-opp/blog_os/tree/post-02) we were able to deduce
enough about the structures to make this tool work.

That being said, Apple can (and will?) change any of these layouts at any time,
certainly between major releases but also within a patch (though the latter is
less likely).

Regarding `Hypervisor.framework`'s `hv_vcpu_read_register()`, first given
DTrace's design center it can't call a user space function (which is a good
thing).  Second, while it's possible to implement the same logic from
`Hypervisor.framework`, you're dealing with `user` addresses, which makes it
difficult to reason about the addresses in question, and unnecessary since
there is a `kernel` address sitting in `curthread` and `curtask` just waiting
for your usage.
