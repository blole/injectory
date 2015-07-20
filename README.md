# CLI DLL-Injector
Imported from https://code.google.com/p/injector/

## About
Loader is an easy to use application that was designed to help you inject DLL libraries into running processes. The utility stops the process during injection. Loader will also provide you with detailed information if errors occur.

- Complete control via the command line (Batch scriptable)
- Target process is stopped during the injection
- Output of all error messages
- Map a PE file into the remote adress space of a process (without calling LoadLibrary).
- Dump modules associated with the specified process id.
- Inject x86 code into a x86 process (Use x86 loader)
- Inject x64 code into a x64 process (Use x64 loader)

Tested on Windows XP/Vista/7.

## Usage
injection via process id:  
`newloader --lib "C:\test.dll" --pid 0xD6C`

injection via process name:  
`newloader --lib "C:\test.dll" --procname "TARGET.exe"`

injection via window title:  
`newloader --lib "C:\test.dll" --wndtitle "Window Title"`

injection via window class:  
`newloader --lib "C:\test.dll" --wndclass "ArenaNet_Dx_Window_Class"`

injection on startup:  
`newloader --lib "C:\test.dll" --launch "C:\TARGET.exe" [--args "TARGET.exe param1 param2"] [--wii]`

ejection via module address:  
`newloader --lib 0x74FE0000 --procname "TARGET.exe" --eject`

ejection via module path:  
`newloader --lib "C:\test.dll" --procname "TARGET.exe" --eject`

injection/ ejection with "SeDebugPrivilege":  
`newloader --lib "C:\test.dll" --procname "TARGET.exe" --dbgpriv`

manual map:  
`newloader --lib "C:\test.dll" --procname "TARGET.exe" --mm`

list all modules:  
`newloader --listmodules 0x123 > modules.txt`

## Credits
- typ312
- ACB
