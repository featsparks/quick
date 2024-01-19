#!/bin/sh

busybox insmod rust_print.ko
busybox  rmmod rust_print.ko

busybox insmod rust_out_of_tree.ko
busybox  rmmod rust_out_of_tree.ko

busybox reboot -f
