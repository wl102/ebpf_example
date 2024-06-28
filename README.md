# ebpf_example

## what is eBPF
https://ebpf.io/zh-cn/what-is-ebpf/

## go ebpf工具链版本要求和参考文档
[quick start](https://ebpf-go.dev/guides/portable-ebpf/)
工具链介绍和要求

[github example](https://github.com/cilium/ebpf/blob/main/examples/tracepoint_in_c/tracepoint.c)
/headers目录下是需要依赖的头文件

编译连接命令
```bash
go get github.com/cilium/ebpf/cmd/bpf2go 
go generate 
go build
sudo ./your_exe
```

## kprobe实现
```c
//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32); //pid
	__type(value, char); // cmdline
} pid_comm_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve() 
{
    u32 pid = bpf_get_current_pid_tgid();
    char comm[256];

    bpf_get_current_comm(&comm, sizeof(comm));
	bpf_map_update_elem(&pid_comm_map, &pid, &comm, BPF_ANY);
	return 0;
}
```

```go
// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf kprobe.c

var maps = make(map[string]uint32)

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		s, err := formatMapContents(objs.PidCommMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val string
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		
		cmd := val
		if _, ok := maps[cmd]; !ok {
			pid := key
			maps[cmd] = pid
			sb.WriteString(fmt.Sprintf("\t%s => %d\n", cmd, pid))
		}
	}
	return sb.String(), iter.Err()
}

```
## tracing实现

```c
// trace.c
//go:build ignore

#include "common.h"
#include "bpf_tracing.h"


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32); //pid
	__type(value, struct Info);
} pid_comm_map SEC(".maps");

struct Info {
    char name[256];
    char args[256];
};

struct syscalls_enter_exec_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char * filename;
    const char *const * argv;
    const char *const *envp;
};

static __always_inline int safe_probe_read_str(char *dst, u32 size, const char *unsafe_ptr) {
    #pragma unroll
    for (int i = 0; i < size; i += sizeof(long)) {
        long val = 0;
        bpf_probe_read(&val, sizeof(val), (const void *)(unsafe_ptr + i));
        bpf_probe_read(dst + i, sizeof(val), &val);
    }
    return 0;
}

// 跟踪 sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_exec(struct syscalls_enter_exec_args *ctx) {
    const char *argp;
    struct Info info = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 从用户空间读取 filename
    if (safe_probe_read_str(info.name, sizeof(info.name), ctx->filename) == 0) {
        // 确保字符串以 '\0' 结尾
        info.name[sizeof(info.name) - 1] = '\0';
        
        // 将 filename 存储到 BPF 映射中
        //bpf_map_update_elem(&pid_comm_map, &pid, filename, BPF_ANY);
    }

    // 从用户空间读取 argv[0]
    if (bpf_probe_read(&argp, sizeof(argp), &ctx->argv[0]) == 0) {
        if (safe_probe_read_str(info.args, sizeof(info.args), argp) == 0) {
            // 确保字符串以 '\0' 结尾
            info.args[sizeof(info.args) - 1] = '\0';

            // 将 argv[0] 存储到 BPF 映射中
            //bpf_map_update_elem(&pid_comm_map, &pid, info.args, BPF_ANY);
        }
    }
    bpf_map_update_elem(&pid_comm_map, &pid, &info, BPF_ANY);
    return 0;
}

```

```go
// main.go
// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/tracing/trace_pipe.
package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf trace.c

var maps = make(map[uint32]bpfInfo)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/tracing/events/kmem/mm_page_alloc
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceEnterExec, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		s, err := formatMapContents(objs.PidCommMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val bpfInfo
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		pid := key
		if _, ok := maps[pid]; !ok {
			cmd := val
			maps[pid] = cmd
			sb.WriteString(fmt.Sprintf("[pid]:%d => [filename]:%s => [args]:%s\n", pid, int8ToString(cmd.Name), int8ToString(cmd.Args)))
		}
	}
	return sb.String(), iter.Err()
}

func int8ToString(arr [128]int8) string {
	buf := make([]byte, len(arr))
	for i := 0; i < 128; i++ {
		if arr[i] == 0 {
			break
		}
		buf[i] = byte(arr[i])
	}
	return string(buf)
}

```