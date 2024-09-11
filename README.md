# Malware Development Advanced Course Vol. 1 Project

## Aim
To get a snapshot of `lsass.exe` through 'middle man' application, in this case `procexp64.exe`. The loader/dropper application will load code in `procexp64.exe` or any other elevated process, which will then open a handle to `lsass.exe`, duplicate the handle and capture a snapshot of the duplicated `lsass.exe` handle. This handle can then be minidumped.

### Detour
There is a change in the implementation of the modules from the course project. 

The course project uses a COFF parser/loader to load and execute a Windows `.obj`  file, which is contained in a Windows COFF file.

This project uses a [sexe](https://medium.com/@nihal.kenkre/sexe-small-exe-e2f8b9acc805) executable, which replicates the functionality of the COFF module, through a simpler, smaller footprint.

## Modules
### Loader
Implemented in `base.c`. 

It loads the sexe file into its memory and executes it in a new thread.

### Stage 1
Implemented in `stage1.x64.asm`.

- It finds the `procexp64.exe` process, and opens a handle to a thread. 
- Allocates memory for Stage 2 in the process. 
- Writes the code and required parameters to the memory.
- Suspends the target thread and gets the context, which is used by `NtContinue` in stage 2.
- Calls `RtlRemoteCall` on the thread, pointing to the stage 2 memory.
- Cleans up the remote memory after execution.
- Duplicates the handle received from stage 2.
- Creates a snapshot of the handle, which can be minidumped.
- Closes all the handles acquired during the execution.

### Stage 2
Implemented in `stage2.x64.asm`.

- Opens a handle to the `lsass.exe` process.
- Saves the handle in memory which is to be read by stage 1.
- Closes the handle.
- Continues the execution of the thread using `NtContinue`.
