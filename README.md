# GoProcessInject0r
Proof of concept for single/multiple shellcode process injection malware in Go language.

Contains two programs:

Multi: 
multi-threaded malware to recursively scan and inject multiple processes' space with little cpu and memory usage

Single: 
malware to scan for target processes once a target process id is found the program will inject shellcode into target process space and exit

Build:
```
admin@local:~$ go get "github.com/TheTitanrain/w32"
admin@local:~$ set GOARCH=386
admin@local:~$ go build -ldflags "-H windowsgui" <single/multi>.go
```

Fully Undetectable 03-02-2020

![multi](https://user-images.githubusercontent.com/51238001/73690648-c0c8a580-46c8-11ea-8f91-1a840cb762c6.png)
