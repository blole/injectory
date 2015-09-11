# injectory
A command-line interface DLL injector for injecting/ejecting DLL libraries into running/new processes.
Uses LoadLibrary (or alternatively a manual version) and CreateRemoteThread.

- The target process is suspended during injection
- Can map a PE file into the remote adress space of a process (without calling LoadLibrary)
- Inject x86 code into a x86 process

## Usage
```
Examples:
  injectory -l a.exe -i b.dll --args "1 2 3" --wii
  injectory -p 12345 -i b.dll --mm --wait-for-exit

Options:
  -p [ --pid ] <pid>     injection via process id
  -l [ --launch ] <exe>  launches the target in a new process
  --args <string>        arguments for --launch:ed process

  -i [ --inject ] <dll>  inject libraries
  -e [ --eject ] <dll>   eject libraries

  --mm                   map the PE file into the target's address space
  --dbgpriv              set SeDebugPrivilege
  --print-pid            print the pid of the (started) process
  --vs-debug-workaround  workaround threads left suspended when debugging with
                         visual studio by resuming all threads for 2 seconds
  --wii                  wait for target input idle before injecting
  --wait-for-exit        wait for the target to exit before exiting
  --kill-on-exit         kill the target when exiting

  -v [ --verbose ]
  --version              display version information and exit
  --help                 display help message and exit
```

## Credits
Imported from https://code.google.com/p/injector/
- Wadim E. (wdmegrv@gmail.com)
- typ312
- ACB
