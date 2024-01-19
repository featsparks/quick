#!/usr/bin/env python3

import re
import sys

PATTERNS = {
    b"No such file or directory": [],
    rb"\bpanic\b": [
        # In local use cases I used this kernel command line.
        #b"oops=panic",

        b"/ledtrig-panic.o",
        b"/panic.o",
    ],
    rb"\bpanics\b": [],
    rb"\boops\b": [
        # In local use cases I used this kernel command line.
        #b"oops=panic",
    ],
    rb"\boopses\b": [],
    rb"\btaint\b": [
        # In local use cases I used a tainted kernel.
        #b"For a more detailed explanation of the various taint flags see",
        #b"Raw taint value as int/string: ",
    ],
    rb"\btaints\b": [
        b"rust_out_of_tree: loading out-of-tree module taints kernel.",
    ],
    rb"\bfault\b": [
        b"/subdev/fault/",

        b"/fault-armv.o",
        b"/fault.o",
    ],
    rb"\bfaults\b": [],
    rb"\bcorrupted\b": [],
    rb"\btrace\b": [
        b"] RCU Tasks Trace:",
        b"] trace event string verifier disabled",
        b".pcie: probe with driver pci-host-generic failed with error -16",

        b"drivers/gpu/trace/",
        b"kernel/trace/",

        b"/amd-pstate-trace.o",
        b"/cdns3-trace.o",
        b"/coresight-trace-id.o",
        b"/fsl-edma-trace.o",
        b"/libata-trace.o",
        b"/mei-trace.o",
        b"/trace.o",
        b"/v4l2-trace.o",
        b"/vb2-trace.o",
        b"/xhci-trace.o",
    ],
    rb"\btraces\b": [
        b"kernel/trace/",

        b"/iommu-traces.o",
        b"/net-traces.o",
    ],
    rb"\bbug\b": [
        b" and report a bug",
        b"*** may not work due to a bug (https://github.com/rust-lang/rust-bindgen/pull/2824),",

        b"/bug.h",
        b"/bug.o",
    ],
    rb"\bbugs\b": [
        b"/bugs.o",
        b"/proc-v7-bugs.o",
    ],
    rb"\berror\b": [
        b"message (level 3)",
        b"regulatory.db",
        b".pcie: probe with driver pci-host-generic failed with error -16",
        b"rust/kernel/error.rs",
        b"Error: Driver 'cpufreq-dt' is already registered, aborting...",

        # These come from the KUnit tests that exercises that.
        #
        # TODO: it would be nice to avoid allowing these by checking the context, i.e.
        # the lines around it.
        #
        # I cannot use `\r\n` at the end to make the numbers limited to these two
        # because in the CI I see just `\n`.
        b"rust_kernel: attempted to create `Error` with out of range `errno`: 0",
        b"rust_kernel: attempted to create `Error` with out of range `errno`: -1000000",

        b"/error.ko",
        b"/error.mod.o",
        b"/error.o",

        # Temporarily allowed for stable kernels (pin-init undocumented safety warning).
        b"inner <- PinInit::<_, error::Error>::pin_chain(Opaque::new(tag_set?), |tag_set| {",
    ],
    rb"\berrors\b": [
        b"/errors.o",
    ],
    rb"\bwarning\b": [
        b"message (level 4)",

        # `um` (i.e. UML) only -- it would be nice to not allow this one for other architectures.
        b"has a LOAD segment with RWX permissions",

        # Temporarily allowed for stable kernels (pin-init undocumented safety warning).
        b"note: this warning originates in the macro `$crate::__init_internal` which comes from the expansion of the macro `pin_init` (in Nightly builds, run with -Z macro-backtrace for more info)",
        b"note: this warning originates in the macro `$crate::__init_internal` which comes from the expansion of the macro `try_init` (in Nightly builds, run with -Z macro-backtrace for more info)",
        b"note: this warning originates in the macro `$crate::__init_internal` which comes from the expansion of the macro `try_pin_init` (in Nightly builds, run with -Z macro-backtrace for more info)",
        b"note: this warning originates in the macro `$crate::__pin_data` which comes from the expansion of the attribute macro `pin_data` (in Nightly builds, run with -Z macro-backtrace for more info)",
        b"warning: unsafe block missing a safety comment",

        # Temporarily allowed for stable kernels.
        b" warning generated.",
        b") in 'do_sys_poll' [-Wframe-larger-than]",
        b") in 'mas_wr_spanning_store' [-Wframe-larger-than]",
        b") in 'mas_wr_store_entry' [-Wframe-larger-than]",
        b"warning emitted",
        b"warning: manual implementation of `Option::filter`",
        b"warning: this `if` can be collapsed into the outer `match`",
        b"warnings emitted",

    ],
    rb"\bwarnings\b": [
        b" warnings generated.",
    ],

    # For KUnit tests.
    rb"\bnot ok\b": [],
    rb"\bASSERTION FAILED\b": [],

    # For `kallsyms` (that does not add warning nor error).
    rb"\bKSYM_NAME_LEN\b": [],
}

def main():
    ok = True
    with open(sys.argv[1], "rb") as file:
        for line in file:
            for pattern in PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    for allowed_string in PATTERNS[pattern]:
                        if allowed_string in line:
                            break
                    else:
                        ok = False
                        print("Bad line found in log:")
                        print(f"    Line:    {line}")
                        print(f"    Pattern: {pattern}")
                        print(f"    Allowed: {PATTERNS[pattern]}")
                        print()

    if not ok:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
