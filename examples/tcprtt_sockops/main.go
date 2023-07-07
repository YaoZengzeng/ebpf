//go:build linux

// This program demonstrates attaching an eBPF program to
// a cgroupv2 path and using sockops to process TCP socket events.
// 这个程序模拟关联一个eBPF程序到一个cgroup path并且使用socket来处理TCP socket events
// It prints the IPs/ports/RTT information every time TCP sockets
// update their internal RTT value.
// 它输出IPs/ports/RTT信息，每次TCP sockets更新它们的internal RTT value
// It supports only IPv4 for this example.
// 李自力只支持IPv4
//
// Sample output:
//
// examples# go run -exec sudo ./tcprtt_sockops
// 2022/08/14 20:58:03 eBPF program loaded and attached on cgroup /sys/fs/cgroup/unified
// 2022/08/14 20:58:03 Src addr        Port   -> Dest addr       Port   RTT (ms)
// 2022/08/14 20:58:09 10.0.1.205      54844  -> 20.42.73.25     443    67
// 2022/08/14 20:58:09 10.0.1.205      54844  -> 20.42.73.25     443    67
// 2022/08/14 20:58:33 10.0.1.205      38620  -> 140.82.121.4    443    26
// 2022/08/14 20:58:33 10.0.1.205      38620  -> 140.82.121.4    443    26
// 2022/08/14 20:58:43 34.67.40.146    45380  -> 10.0.1.205      5201   106
// 2022/08/14 20:58:43 34.67.40.146    45380  -> 10.0.1.205      5201   106
//
// sudo cat /sys/kernel/debug/tracing/trace_pipe
// 查看sockmap日志
//
// tcpdump -i lo port 1000 -vvv
// 确认包跳过了协议栈

package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "linux" -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcprtt_sockops.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Find the path to a cgroup enabled to version 2
	// 找到到一个cgroup path，对于version 2
	cgroupPath, err := findCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	// 加载提前编译的programs以及maps到内核
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach ebpf program to a cgroupv2
	// 关联ebpf程序到cgroupv2
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.bpfPrograms.BpfSockopsCb,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.bpfMaps.SockOpsMap.FD(),
		Program: objs.bpfPrograms.BpfRedir,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.bpfMaps.SockOpsMap.FD(),
			Program: objs.bpfPrograms.BpfRedir,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
		if err != nil {
			log.Fatal(err)
		}
	}()

	// eBPF程序加载并且关联到cgroup
	log.Printf("eBPF program loaded and attached on cgroup %s\n", cgroupPath)

	// Wait
	<-stopper
}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, nil
}
