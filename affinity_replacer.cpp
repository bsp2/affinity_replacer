
// affinity_replace.cpp
//   by bsp [02Oct2021, 03Oct2021, 04Oct2021]
//   this is public domain software, do what you want
// ----          THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// ----          NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// ----          IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// ----          WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
// ----          SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


// based on:
//   https://docs.microsoft.com/de-de/windows/win32/psapi/enumerating-all-processes
//   https://docs.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list

// https://stackoverflow.com/questions/35732495/openprocess-access-is-denied-for-some-users
//  => OpenProcessToken, LookupPrivilegeValue and AdjustTokenPrivileges APIs.

// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
// https://docs.microsoft.com/en-us/windows/win32/secgloss/a-gly

// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessaffinitymask
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask
//  (note) returns old affinity mask
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamea
// https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid
// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
// https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-

// (note) PID 0 is "System Idle Process"
// (note) PID 4 is "System"

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif // _CRT_SECURE_NO_DEPRECATE

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PROCESSES 32768
#define MAX_MODULES_PER_PROCESS 1024

typedef unsigned int sUI;
typedef unsigned __int64 sU64;

static BOOL b_verbose = FALSE;
static BOOL b_very_verbose = FALSE;
static BOOL b_dll = FALSE;
static BOOL b_loop = FALSE;
static sU64 system_affinity_mask = 0u;
static sU64 force_affinity_mask = 0u;
static sU64 match_affinity_mask = 0u;
static DWORD match_pid = 0u;
static BOOL b_slow = FALSE;
static BOOL b_error_nonexisting_thread = FALSE;

static BOOL b_update_process_affinity = FALSE;
static BOOL b_update_thread_affinity = FALSE;

static HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 

#define Dprintf   if(!b_verbose) {} else printf
#define D_tprintf if(!b_verbose) {} else _tprintf
#define Dwprintf  if(!b_verbose) {} else wprintf

#define Dvprintf   if(!b_very_verbose) {} else printf
#define Dv_tprintf if(!b_very_verbose) {} else _tprintf
#define Dvwprintf  if(!b_very_verbose) {} else wprintf

#if 0
static void error_string(DWORD _errorCode) {
   LPSTR messageBuffer = nullptr;
   size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
   LocalFree(messageBuffer);
}
#endif


static BOOL iterate_process_threads(DWORD _processID, sU64 _processAffinityMask) {
   THREADENTRY32 te32; 
 
   // Fill in the size of the structure before using it. 
   te32.dwSize = sizeof(THREADENTRY32); 
 
   // Retrieve information about the first thread,
   // and exit if unsuccessful
   if(!Thread32First( hThreadSnap, &te32)) 
   {
      Dprintf("[---] processID=%u Thread32First() failed (hThreadSnap=%p) GetLastError=%u\n", _processID, hThreadSnap, GetLastError());
      return FALSE;
   }

   // Now walk the thread list of the system,
   // and display information about each thread
   // associated with the specified process
   do 
   { 
      if(te32.th32OwnerProcessID == _processID)
      {
         Dv_tprintf( TEXT("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID ); 
         Dv_tprintf( TEXT("\n     base priority  = %d"), te32.tpBasePri ); 
         Dv_tprintf( TEXT("\n     delta priority = %d"), te32.tpDeltaPri ); 

         HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,
                                     FALSE/*bInheritHandle*/,
                                     te32.th32ThreadID
                                     );
         if(NULL != hThread)
         {
            Dvprintf("\n[+++] processID=%u th32ThreadID=%u OpenThread() succeeded\n", _processID, te32.th32ThreadID);

            DWORD_PTR newMask = (sU64) ((0u != force_affinity_mask) ? (force_affinity_mask & _processAffinityMask) : (system_affinity_mask & _processAffinityMask));
            if(0u != newMask)
            {
               DWORD_PTR oldMask = SetThreadAffinityMask(hThread, newMask);
               if(oldMask)
               {
                  sU64 oldMask64 = (sU64)oldMask;
                  Dvprintf("\n[dbg] processID=%u th32ThreadID=%u threadAffinityMask=0x%llx\n", _processID, te32.th32ThreadID, oldMask64);

                  if(!b_update_thread_affinity || ((0u != match_affinity_mask) && (0u == (oldMask64 & match_affinity_mask))) )
                  {
                     // Restore old mask
                     (void)SetThreadAffinityMask(hThread, oldMask);
                  }
                  else
                  {
                     if(oldMask64 != (sU64)newMask)
                        Dprintf("\n[+++] processID=%u, updated th32ThreadID=%u affinity mask to 0x%llx (was 0x%llx)\n", _processID, te32.th32ThreadID, (sU64)newMask, oldMask64);
                  }
               }
               else
               {
                  Dprintf("\n[---] SetThreadAffinityMask() failed, processId=%u th32ThreadID=%u. oldMask=0x%llx GetLastError=%u\n", _processID, te32.th32ThreadID, (sU64)oldMask, GetLastError());
               }
            }

            CloseHandle(hThread);
         }
         else
         {
            DWORD lastError = GetLastError();
            // 87=ERROR_INVALID_PARAMETER, raised when thread does not exist anymore,
            //     see https://stackoverflow.com/questions/20143364/openthread-with-a-nonexistent-thread-id
            if(b_error_nonexisting_thread || (87 != lastError))
            {
               Dprintf("\n[---] processID=%u th32ThreadID=%u OpenThread() failed GetLastError=%u\n", _processID, te32.th32ThreadID, lastError);
            }
         }

         if(b_slow)
            Sleep(1/*ms*/);   // yield CPU to other processes
         
      }
   } while(Thread32Next(hThreadSnap, &te32 ));

   Dv_tprintf( TEXT("\n"));

   return TRUE;
}

static void iterate_process(DWORD _processID) {

   // Get a handle to the process.
   // DWORD dwDesiredAccess = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
   DWORD dwDesiredAccess = PROCESS_ALL_ACCESS;
   // DWORD dwDesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
   HANDLE hProcess = OpenProcess(dwDesiredAccess,
                                 FALSE/*bInheritHandle*/,
                                 _processID
                                 );

   // Get the process name.
   if(NULL != hProcess )
   {

      // (note) first handle is .exe, other ones are .dlls
      HMODULE hMod[MAX_MODULES_PER_PROCESS];
      DWORD hModSz;

      DWORD_PTR dwProcessAffinityMask;
      DWORD_PTR dwSystemAffinityMask;
      if(GetProcessAffinityMask(hProcess,
                                &dwProcessAffinityMask/*lpProcessAffinityMask*/,
                                &dwSystemAffinityMask/*lpSystemAffinityMask*/
                                )
         )
      {
         Dvprintf("[...] processID=%u dwProcessAffinityMask=0x%llx dwSystemAffinityMask=0x%llx\n", _processID, dwSystemAffinityMask, dwSystemAffinityMask);
         system_affinity_mask = (sU64)dwSystemAffinityMask;  // e.g. 0x3FFFF = 18 cores

         if( (0u == match_affinity_mask) || (0u != (system_affinity_mask & match_affinity_mask)) )
         {
            if(dwProcessAffinityMask != dwSystemAffinityMask)
            {
               Dvprintf("[...] processID=%u custom dwProcessAffinityMask=0x%llx\n", _processID, dwProcessAffinityMask);
            }

            if(b_update_process_affinity)
            {
               sU64 newAffinityMask = (0u != force_affinity_mask) ? (force_affinity_mask & system_affinity_mask) : system_affinity_mask;
               if(0u != newAffinityMask)
               {
                  if( (0u == match_affinity_mask) || (0u != (dwProcessAffinityMask & match_affinity_mask)) )
                  {
                     if(SetProcessAffinityMask(hProcess,
                                               (DWORD_PTR)newAffinityMask
                                               )
                        )
                     {
                        if(newAffinityMask != dwProcessAffinityMask)
                           printf("[+++] processID=%u updated process affinity mask to 0x%llx\n", _processID, newAffinityMask);
                     }
                  }
               }
            }

            if(EnumProcessModules(hProcess, hMod, sizeof(hMod), 
                                  &hModSz
                                  )
               )
            {
               sUI numModules = hModSz / sizeof(HMODULE);
               TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
               if(!b_dll)
                  numModules = 1u;

               for(sUI moduleIdx = 0u; moduleIdx < numModules; moduleIdx++)
               {
                  GetModuleBaseName(hProcess,
                                    hMod[moduleIdx],
                                    szProcessName, 
                                    sizeof(szProcessName)/sizeof(TCHAR)
                                    );

                  // Print the process name and identifier.
                  Dv_tprintf( TEXT("PID: %u Module: %u/%u Name: \"%s\"\n"), _processID, (moduleIdx+1u), numModules, szProcessName);
               }

               iterate_process_threads(_processID, dwProcessAffinityMask);
            }
            else
            {
               Dprintf("[~~~] processID=%u EnumProcessModules() failed\n", _processID);
            }
         }
      }

   }
   else
   {
      // (note) error 5 is "access denied"
      Dvprintf("[~~~] processID=%u => hProcess=NULL!! GetLastError=%u\n", _processID, GetLastError());
   }

   // Release the handle to the process.
   CloseHandle(hProcess);
}

static void Usage(const char *_exeName) {
   printf("Usage: %s [/v] [/vv] [/d] [/f <force_affinity_hex_mask>] [/m <match_affinity_hex_mask>] [/p <PID>] [/ne] [/l] [/slow]\n", _exeName);
   printf("   /v    : verbose output\n");
   printf("   /vv   : very verbose output (DEBUG)\n");
   printf("   /d    : list DLL modules (DEBUG)\n");
   printf("   /f    : update thread affinity masks that match (AND) <match_mask>\n");
   printf("   /m    : set match mask\n");
   printf("   /p    : set process ID filter to <PID>\n");
   printf("   /ne   : report error when (short-lived) thread does not exist anymore (after enumeration) (DEBUG)\n");
   printf("   /l    : run in a loop (continously update affinity masks)\n");
   printf("   /slow : lower CPU usage by Sleep()ing during thread/process iteration (~45sec per complete cycle)\n");
   printf("\n");
   printf("Examples:\n");
   printf("                   %s /v : List all processes/modules/threads and their current affinity masks (don\'t change anything)\n", _exeName);
   printf("    %s /f 2000F /m 20000 : Force affinity mask=core 1,2,3,4,18 for all threads that can currently run on core 18\n", _exeName);
   printf("    %s /f 2000F /m 1FFF0 : Force affinity mask=core 1,2,3,4,18 for all threads that can currently run on cores 5..17\n", _exeName);
   printf("        %s /f 0 /m 20000 : Reset affinity masks for all threads that can currently run on core 18\n", _exeName);
   printf("        %s /f 0 /m 2000F : Reset affinity masks for all threads that can currently run on cores 1,2,3,4,18\n", _exeName);
   printf("            %s /f F /m F : Force affinity mask=core 1..4 for all threads that _can_ currently run on cores 1..4\n", _exeName);
   printf("\n");
   printf("Affinity masks:\n");
   printf("  a (hexadecimal) bit-mask where bit <n> indicates that a thread may run on core <n+1>\n");
   printf("  for example, mask=1 (bit 0 set) means \"may run on core 1\" mask=2 means \"may run on core 2\", mask=3 means \"may run on core 1 or 2\"\n");
}

int main(int _argc, char **_argv) {
   printf("starting affinity_replacer\n");

   if(1 == _argc)
   {
      Usage(_argv[0]);
      return 0;
   }

   // Parse args
   int argIdx = 1;
   while(argIdx < _argc)
   {
      const char *arg = _argv[argIdx];
      if(!strcmp(arg, "/v"))
      {
         b_verbose = TRUE;
         printf("[...] enabling verbose output (/v)\n");
      }
      else if(!strcmp(arg, "/vv"))
      {
         b_very_verbose = TRUE;
         printf("[...] enabling very verbose output (/vv)\n");
      }
      else if(!strcmp(arg, "/d"))
      {
         b_dll = TRUE;
         printf("enabling DLL module debug output (/d)\n");
      }
      else if(!strcmp(arg, "/f"))
      {
         if((argIdx+1) < _argc)
         {
            sscanf(_argv[argIdx+1], "%llx", &force_affinity_mask);
            printf("[...] force_affinity_mask=0x%llx (/f)\n", force_affinity_mask);
            b_update_process_affinity = TRUE;
            b_update_thread_affinity  = TRUE;
            argIdx++;
         }
         else
         {
            printf("[---] /f : expect affinity mask arg\n");
            return 10;
         }
      }
      else if(!strcmp(arg, "/m"))
      {
         if((argIdx+1) < _argc)
         {
            sscanf(_argv[argIdx+1], "%llx", &match_affinity_mask);
            printf("[...] match_affinity_mask=%llx (/m)\n", match_affinity_mask);
            argIdx++;
         }
         else
         {
            printf("[---] /m : expect affinity mask arg\n");
            return 10;
         }
      }
      else if(!strcmp(arg, "/l"))
      {
         b_loop = TRUE;
         printf("[...] enabling loop mode (/l)\n");
      }
      else if(!strcmp(arg, "/p"))
      {
         if((argIdx+1) < _argc)
         {
            sscanf(_argv[argIdx+1], "%u", &match_pid);
            printf("[...] match_pid=%u (/p)\n", match_pid);
            argIdx++;
         }
         else
         {
            printf("[---] /m : expect affinity mask arg\n");
            return 10;
         }
      }
      else if(!strcmp(arg, "/ne"))
      {
         b_error_nonexisting_thread = TRUE;
         printf("[...] reporting non-existing thread errors (/ne)\n");
      }
      else if(!strcmp(arg, "/slow"))
      {
         b_slow = TRUE;
         printf("[...] enabling slow mode (/slow)\n");
      }

      // Next arg
      argIdx++;
   }

   // Get privilege
   HANDLE hToken = NULL;
   HANDLE hProcessSelf = GetCurrentProcess();
   if(OpenProcessToken(hProcessSelf, TOKEN_ALL_ACCESS, &hToken))
   {
      // see TOKEN_PRIVILEGES
      struct {
         DWORD               PrivilegeCount;
         LUID_AND_ATTRIBUTES Privileges[1];
      } tokenPrivileges;

      memset((void*)&tokenPrivileges, 0, sizeof(tokenPrivileges));

      BOOL bOk = TRUE;
      LUID luid;
      const wchar_t *name = SE_DEBUG_NAME;//SE_ASSIGNPRIMARYTOKEN_NAME;
      bOk = LookupPrivilegeValue(NULL,   // lookup privilege on local system
                                 name,   // privilege to lookup 
                                 &luid   // receives LUID of privilege
                                 );
      if(bOk)
      {
         tokenPrivileges.PrivilegeCount = 1u;
         tokenPrivileges.Privileges[0].Luid = luid;
         tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

         if(AdjustTokenPrivileges(hToken,
                                  FALSE/*DisableAllPrivileges*/,
                                  (PTOKEN_PRIVILEGES)&tokenPrivileges,
                                  0/*BufferLength*/,
                                  NULL/*PreviousState*/,
                                  0/*ReturnLength*/
                                  )
            )
         {
            Dprintf("[...] ok, AdjustTokenPrivileges() succeeded\n");
         }
         else
         {
            Dprintf("[~~~] AdjustTokenPrivileges() failed. GetLastError=%u\n", GetLastError());
         }
      }
      else
      {
         Dwprintf(TEXT("[---] LookupPrivilegeValue() failed (name=\"%s\"). GetLastError=%u\n"), name, GetLastError()); 
      }
         
   }
   else
   {
      Dprintf("[~~~] OpenProcessToken() failed\n");
   }

   if(NULL != hToken)
   {
      // Enumerate processes
      do
      {
         DWORD processes[MAX_PROCESSES];
         DWORD processesSz;
         sUI numProcesses;

         if(!EnumProcesses(processes, sizeof(processes), &processesSz))
         {
            printf("[---] EnumProcesses failed.\n");
            return 10;
         }

         // Calculate how many process identifiers were returned.
         numProcesses = processesSz / sizeof(DWORD);

         // Take a snapshot of all running threads  
         hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
         if(INVALID_HANDLE_VALUE == hThreadSnap)
         {
            printf("[~~~] CreateToolhelp32Snapshot() failed. GetLastError=%u\n", GetLastError());
            CloseHandle(hToken);
            return 10; 
         }

         // Print the name and process identifier for each process.
         for(sUI i = 0u; i < numProcesses; i++)
         {
            if(0u != processes[i])
            {
               if( (0u == match_pid) || (match_pid == processes[i]) )
               {
                  Dvprintf("processes[i] = %u\n", processes[i]);

                  iterate_process(processes[i]);

                  if(b_slow)
                     Sleep(1/*milliSeconds*/);  // yield CPU to other processes
               }
            }
         }

         //  Don't forget to clean up the snapshot object.
         CloseHandle(hThreadSnap);

         Dprintf("[trc] next loop iteration @t=%u\n", GetTickCount());

      } while(b_loop);

      CloseHandle(hToken);
   }

   return 0;
}
