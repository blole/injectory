# injectory
A command-line interface DLL injector for injecting/ejecting DLL libraries into running/new processes.
Uses LoadLibrary (or alternatively a manual version) and CreateRemoteThread.

- The target process is suspended during injection
- Can map a PE file into the remote adress space of a process (without calling LoadLibrary)
- Inject x86 code into a x86 process

## Usage
```
usage: injectory TARGET [OPTION]...
inject DLL:s into processes

Examples:
  injectory --launch a.exe --map b.dll --args "1 2 3"
  injectory --pid 12345 --inject b.dll --wait-for-exit

Targets:
  -p [ --pid ] PID         injection via process id
  -l [ --launch ] EXE      launches the target in a new process
  -a [ --args ] STRING     arguments for --launch:ed process

Options:
  -i [ --inject ] DLL...   inject libraries before main
  -I [ --injectw ] DLL...  inject libraries when input idle
  -m [ --map ] DLL...      map file into target before main
  -M [ --mapw ] DLL...     map file into target when input idle
  -e [ --eject ] DLL...    eject libraries before main
  -E [ --ejectw ] DLL...   eject libraries when input idle

  --print-own-pid          print the pid of this process
  --print-pid              print the pid of the target process
  --rethrow                rethrow exceptions
  --vs-debug-workaround    workaround for threads left suspended when debugging
                           with visual studio by resuming all threads for 2
                           seconds
  --dbgpriv                set SeDebugPrivilege
  --wait-for-exit          wait for the target to exit before exiting
  --kill-on-exit           kill the target when exiting

  -v [ --verbose ]
  --version                display version information and exit
  --help                   display help message and exit
```

## Credits
Imported from https://code.google.com/p/injector/
- Wadim E. (wdmegrv@gmail.com)
- typ312
- ACB
