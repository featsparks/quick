#!/usr/bin/env python3

import argparse
import re

class Allowed:
    """An allowed string, optionally scoped to a given architecture and/or tree.

    `arch` must match exactly. `tree` matches as a substring, so that e.g. "6.12"
    covers both "stable-rc/linux-6.12.y" and "stable-rc/queue/6.12".
    """
    def __init__(self, string, *, arch=None, tree=None):
        self.string = string
        self.arch = arch
        self.tree = tree

    def matches(self, line, arch, tree):
        if self.arch is not None and self.arch != arch:
            return False
        if self.tree is not None and self.tree not in tree:
            return False
        return self.string in line

    def __repr__(self):
        scope = ""
        if self.arch is not None:
            scope += f", arch={self.arch!r}"
        if self.tree is not None:
            scope += f", tree={self.tree!r}"
        return f"Allowed({self.string!r}{scope})"

PATTERNS = {
    b"No such file or directory": [],
    rb"\bpanic\b": [
        # In local use cases I used this kernel command line.
        #Allowed(b"oops=panic"),

        Allowed(b"/ledtrig-panic.o"),
        Allowed(b"/panic.o"),

        # `um` 6.12.y: include chains ("In file included from ...") of the
        # `-Wnull-pointer-arithmetic` flood (see the `warning` pattern).
        Allowed(b"kernel/panic.c:", arch="um", tree="6.12"),
    ],
    rb"\bpanics\b": [],
    rb"\boops\b": [
        # In local use cases I used this kernel command line.
        #Allowed(b"oops=panic"),
    ],
    rb"\boopses\b": [],
    rb"\btaint\b": [
        # In local use cases I used a tainted kernel.
        #Allowed(b"For a more detailed explanation of the various taint flags see"),
        #Allowed(b"Raw taint value as int/string: "),
    ],
    rb"\btaints\b": [
        Allowed(b"rust_out_of_tree: loading out-of-tree module taints kernel."),
    ],
    rb"\bfault\b": [
        Allowed(b"/subdev/fault/"),

        Allowed(b"/fault-armv.o"),
        Allowed(b"/fault.o"),
    ],
    rb"\bfaults\b": [],
    rb"\bcorrupted\b": [],
    rb"\btrace\b": [
        Allowed(b"] RCU Tasks Trace:"),
        Allowed(b"] trace event string verifier disabled"),
        Allowed(b".pcie: probe with driver pci-host-generic failed with error -16"),

        Allowed(b"drivers/gpu/trace/"),
        Allowed(b"kernel/trace/"),

        Allowed(b"/amd-pstate-trace.o"),
        Allowed(b"/cdns3-trace.o"),
        Allowed(b"/cdnsp-trace.o"),
        Allowed(b"/coresight-trace-id.o"),
        Allowed(b"/fsl-edma-trace.o"),
        Allowed(b"/libata-trace.o"),
        Allowed(b"/mei-trace.o"),
        Allowed(b"/trace.o"),
        Allowed(b"/v4l2-trace.o"),
        Allowed(b"/vb2-trace.o"),
        Allowed(b"/xhci-trace.o"),

        # `um` 6.12.y: include chains ("In file included from ...") of the
        # `-Wnull-pointer-arithmetic` flood (see the `warning` pattern). Matched by
        # path, since parallel build output sometimes corrupts the rest of the line.
        Allowed(b"./include/trace/", arch="um", tree="6.12"),
        Allowed(b"fs/iomap/trace.c", arch="um", tree="6.12"),
    ],
    rb"\btraces\b": [
        Allowed(b"kernel/trace/"),

        Allowed(b"/iommu-traces.o"),
        Allowed(b"/net-traces.o"),
    ],
    rb"\bbug\b": [
        Allowed(b" and report a bug"),
        Allowed(b"*** may not work due to a bug (https://github.com/rust-lang/rust-bindgen/pull/2824),"),
        Allowed(b"MP-BIOS bug: 8254 timer not connected to IO-APIC"),

        Allowed(b"/bug.h"),
        Allowed(b"/bug.o"),
    ],
    rb"\bbugs\b": [
        Allowed(b"/bugs.o"),
        Allowed(b"/proc-v7-bugs.o"),
    ],
    rb"\berror\b": [
        Allowed(b"message (level 3)"),
        Allowed(b"regulatory.db"),
        Allowed(b".pcie: probe with driver pci-host-generic failed with error -16"),
        Allowed(b"rust/kernel/error.rs"),

        # These come from the KUnit tests that exercises that.
        #
        # TODO: it would be nice to avoid allowing these by checking the context, i.e.
        # the lines around it.
        #
        # I cannot use `\r\n` at the end to make the numbers limited to these two
        # because in the CI I see just `\n`.
        Allowed(b"rust_kernel: attempted to create `Error` with out of range `errno`: 0"),
        Allowed(b"rust_kernel: attempted to create `Error` with out of range `errno`: -1000000"),

        Allowed(b"/error.ko"),
        Allowed(b"/error.mod.o"),
        Allowed(b"/error.o"),

        # Temporarily allowed for stable kernels (pin-init undocumented safety warning).
        Allowed(b"inner <- PinInit::<_, error::Error>::pin_chain(Opaque::new(tag_set?), |tag_set| {"),
    ],
    rb"\berrors\b": [
        Allowed(b"/errors.o"),
    ],
    rb"\bwarning\b": [
        Allowed(b"message (level 4)"),

        # loongarch64
        Allowed(b"drivers/gpu/drm/amd/amdgpu/amdgpu_vm.o: warning: objtool: amdgpu_vm_handle_fault+0x", arch="loongarch64"),

        # `um` (i.e. UML) only.
        Allowed(b"has a LOAD segment with RWX permissions", arch="um"),

        # Temporarily allowed for stable kernels (pin-init undocumented safety warning).
        Allowed(b"note: this warning originates in the macro `$crate::__init_internal` which comes from the expansion of the macro `pin_init` (in Nightly builds, run with -Z macro-backtrace for more info)"),
        Allowed(b"note: this warning originates in the macro `$crate::__init_internal` which comes from the expansion of the macro `try_init` (in Nightly builds, run with -Z macro-backtrace for more info)"),
        Allowed(b"note: this warning originates in the macro `$crate::__init_internal` which comes from the expansion of the macro `try_pin_init` (in Nightly builds, run with -Z macro-backtrace for more info)"),
        Allowed(b"note: this warning originates in the macro `$crate::__pin_data` which comes from the expansion of the attribute macro `pin_data` (in Nightly builds, run with -Z macro-backtrace for more info)"),
        Allowed(b"warning: unsafe block missing a safety comment"),

        # `um` 6.12.y only: many, many `warning: performing pointer arithmetic on a null
        # pointer has undefined behavior [-Wnull-pointer-arithmetic]` on the null `PCI_IOBASE`.
        #
        # 6.12.y is the only affected tree: it enables `-Wextra` by default (6.6.y only
        # does so for `W=1`), and 6.13 removed the accessors in commit 6f043e757445
        # ("asm-generic/io.h: Remove I/O port accessors for HAS_IOPORT=n").
        Allowed(b"performing pointer arithmetic on a null pointer has undefined behavior", arch="um", tree="6.12"),
        # Parallel build output sometimes corrupts the flood mid-line (even mid-token),
        # so also allow pieces that survive the interleaving: the file path, the source
        # context lines (`PCI_IOBASE`, the `__raw_*` accessors) and the ten-tilde caret
        # line underlining `PCI_IOBASE`.
        Allowed(b"./include/asm-generic/io.h", arch="um", tree="6.12"),
        Allowed(b"(PCI_IOBASE +", arch="um", tree="6.12"),
        Allowed(b"__raw_read", arch="um", tree="6.12"),
        Allowed(b"__raw_write", arch="um", tree="6.12"),
        Allowed(b"~~~~~~~~~~ ^", arch="um", tree="6.12"),

        # loongarch64 6.12.y many warnings.
        Allowed(b": sibling call from callable instruction with modified stack frame", arch="loongarch64", tree="6.12"),

        # Temporarily allowed for stable kernels.
        Allowed(b" warning generated."),
        Allowed(b") in 'do_sys_poll' [-Wframe-larger-than]"),
        Allowed(b") in 'mas_wr_spanning_store' [-Wframe-larger-than]"),
        Allowed(b") in 'mas_wr_store_entry' [-Wframe-larger-than]"),
        # `um` 6.6.y only.
        Allowed(b") in 'mas_wr_modify' [-Wframe-larger-than]", arch="um", tree="6.6"),
        Allowed(b"warning emitted"),
        Allowed(b"warning: manual implementation of `Option::filter`"),
        Allowed(b"warning: this `if` can be collapsed into the outer `match`"),
        Allowed(b"warnings emitted"),

        # Seen in 6.12.y.
        Allowed(b"mm/slab.h:572:24: warning: duplicate 'inline' declaration specifier [-Wduplicate-decl-specifier]", tree="6.12"),

    ],
    rb"\bwarnings\b": [
        Allowed(b" warnings emitted"),
        Allowed(b" warnings generated."),

        # `um` 6.12.y: corrupted lines of the `-Wnull-pointer-arithmetic` flood
        # (see the `warning` pattern).
        Allowed(b"performing pointer arithmetic on a null pointer has undefined behavior", arch="um", tree="6.12"),
        Allowed(b"./include/asm-generic/io.h", arch="um", tree="6.12"),
        Allowed(b"(PCI_IOBASE +", arch="um", tree="6.12"),
        Allowed(b"__raw_read", arch="um", tree="6.12"),
        Allowed(b"__raw_write", arch="um", tree="6.12"),
        Allowed(b"~~~~~~~~~~ ^", arch="um", tree="6.12"),
    ],

    # For KUnit tests.
    rb"\bnot ok\b": [],
    rb"\bASSERTION FAILED\b": [],

    # For `kallsyms` (that does not add warning nor error).
    rb"\bKSYM_NAME_LEN\b": [
        # `um` 6.12.y, 6.18.y, 7.2.y and 7.3.y `defconfig+debug`: Rust doctest
        # symbols longer than `KSYM_NAME_LEN` (512) get skipped by
        # `scripts/kallsyms` (nonfatal, i.e. they are just missing from
        # `kallsyms`).
        Allowed(b"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c", arch="um", tree="6.12"),
        Allowed(b"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c", arch="um", tree="6.18"),
        Allowed(b"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c", arch="um", tree="7.2"),
        Allowed(b"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c", arch="um", tree="7.3"),
    ],

    rb"\bdeprecated\b": [
        # RISC-V kernel log.
        Allowed(b"Falling back to deprecated \"riscv,isa\""),

        # Workqueue doctests: https://lore.kernel.org/rust-for-linux/CANiq72mmBmdKsXDZuRvcm2_MfjHKzGphdv8_n1FvoV20va4dPA@mail.gmail.com/
        #
        # Also in `_RNvXs8_NtCseUEvc4r6T4f_6kernel9workqueueINtNtNtB7_4sync3arc3ArcNtNtNtNtBH_4lock8spinlock5tests4TestEINtB5_15WorkItemPointerKy0_E3runB7_`.
        Allowed(b"_15WorkItemPointerKy0_E3runB17_ enqueued on deprecated workqueue. Use system_{percpu|dfl}_wq instead."),
        Allowed(b'_15WorkItemPointerKy0_E3runB7_ enqueued on deprecated workqueue. Use system_{percpu|dfl}_wq instead.'),
    ],
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, help="architecture the log comes from, e.g. `x86_64`")
    parser.add_argument("--tree", required=True, help="tree the log comes from, e.g. `stable-rc/linux-6.12.y`")
    parser.add_argument("log")
    args = parser.parse_args()

    ok = True
    with open(args.log, "rb") as file:
        for line in file:
            for pattern in PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    for allowed in PATTERNS[pattern]:
                        if allowed.matches(line, args.arch, args.tree):
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
