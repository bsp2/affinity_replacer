
# affinity_replacer

This is an experimental* multi-processor utility for x64 Windows (10) which relegates background tasks and services to certain CPU cores, by updating their process + thread affinity masks.

The basic idea is that you start a realtime audio application ("DAW"), assign it an affinity mask (e.g. cores 5..18), then force the inverted affinity mask on all other processes by running this utility (preferably in the background / in loop mode since the system may spawn new processes and threads).

*\*experimental means "it won't affect system stability or cause permanent changes but I'm still evaluating / testing it"*


## Usage

~~~
affinity_replacer.exe [/v] [/vv] [/d] [/f <force_affinity_hex_mask>] [/m <match_affinity_hex_mask>] [/p <PID>] [/ne] [/l] [/slow]
    /v    : verbose output
    /vv   : very verbose output (DEBUG)
    /d    : list DLL modules (DEBUG)
    /f    : update thread affinity masks that match (AND) <match_mask>
    /m    : set match mask
    /p    : set process ID filter to <PID>
    /ne   : report error when (short-lived) thread does not exist anymore (after enumeration) (DEBUG)
    /l    : run in a loop (continously update affinity masks)
    /slow : lower CPU usage by Sleep()ing during thread/process iteration (~45sec per complete cycle)
~~~

The utility _must_ be run with administrator privileges.
To do that, search for "Command prompt" in the Windows start menu, then right-click and choose "Run as administrator".


## Examples

### On an 18 core system
~~~
affinity_replacer.exe /v /f F /m F /l /slow
~~~
=> redirects all processes/threads that _can_ run on cores 1..4 to _only_ run on cores 1..4, leaving cores 4..18 to realtime audio tasks..

### On a 10 core system
~~~
affinity_replacer.exe /v /f 3 /m 3 /l /slow
~~~
=> redirects all processes/threads that _can_ run on cores 1+2 to _only_ run on cores 1+2, leaving cores 3..10 to realtime audio tasks.

### On a 6..8 core system
~~~
affinity_replacer.exe /v /f 1 /m 1 /l /slow
~~~
=> redirects all processes/threads that _can_ run on core 1 to _only_ run on cores 1, leaving cores 2..8 to realtime audio tasks.

### Revert changes
~~~
affinity_replacer.exe /v /f 0 /m 1
~~~
=> allow all processes/threads that _can_ run on core 1 to run on any core (0 will be replaced by the system affinity mask).

### Debug-print affinity info for all processes and threads
~~~
affinity_replacer.exe /v /vv
~~~


## Tests

In my test scenarios I am using the (free) "Eureka" VST host that is included with the [Synergy](http://miditracker.org/) MIDI sequencer application running on a Windows 10 pro 64bit system with an Intel 7980xe 18 core CPU, NVidia 1080 TI graphics card, and RME Fireface 802 USB audio (20 analog channels in, 28 analog channels out).

My test project contains 8 tracks and a total of 10 sub-tracks ("lanes") which process external audio from multiple hardware synths and my Eurorack modular using various effect VSTs (like reverbs / delays / a flanger / eqs / compressors) from companies like Arturia, Exponential Audio, Fab Filter, Kush Audio, KV331, MD, PSP, Relab Development, Synapse Audio, Softube, TAL, XILS. This is not meant to be a list of recommendations, Valhalla and U-He make great plugins, too ;) it's just what happened to end up in this particular project (a total of 30 VST instances, by the way).

The audio process was configured to run on cores 5..14, each track was configured to run a dedicated CPU core, and the sequencer process was assigned to cores 16 and 17. The two processes communicate via LoopMIDI loopback devices.

The peak per-track/core CPU load was ~55%, and the total processing time (which includes waiting for worker threads) was ~64% (relative to the ~1.45ms timeslot available for processing 64 sample frame buffers at a rate of 44.1kHz).

The entire system is properly optimized for realtime audio (to my best knowledge), which includes

- using the "high performance" power profile
- turning off unneeded background tasks and services (including the "Microsoft Compatibility Appraiser" tasks, which caused a lot of low-latency issues)
- disabling the system page file (do _not_ do this if you have less than 32GB RAM !)
- using up to date drivers. According to the [LatencyMon](https://www.resplendence.com/latencymon) the "Highest reported DPC routine execution time" is <180us, even with an NVidia 1080 TI graphics card (these used to be notorious for causing realtime audio issues, not any more, as it seems).
- in `systempropertiesadvanced.exe`=>Performance Settings=>Advanced choose "Adjust for best performance of: [*] Background services"
- running the audio process with realtime priority (configured via task manager) (Warning: this can lock up the entire system in case the process gets stuck. fortunately this hasn't happened, yet. Note aside: "Eureka" has a watch dog mechanism to detect this scenario and will stop all audio processing when too many underruns occurs or a worker thread takes too long)

### Scenario 1
In this scenario the computer was used for web browsing, email, and video while the (realtime) music was running in the background.
The first underrun occured after ~7.1 hours.

### Scenario 2
Here I left the computer unattended (over night) with no applications open except for the DAW and sequencer.
The first underrun occured after 1.5h, the next one after 5.6h.
My guess is that some maintenance service started after the computer had been idle for more than an hour.

## Conclusion
My conclusion so far is that this utility indeed reduces the number of underruns in low-latency (64 frames ASIO buffer) audio applications.

It does not completely eliminate them, though.


## Issues
One issue is that in `/slow` mode it takes ~45 seconds to iterate all threads. This means that if a new process / thread is spawned, it can potentially clash with the audio threads scheduling wise for this period of time.

Running the utility without `/slow` causes a relatively high CPU load on the core the utility runs on (cores 1..4 in my setup). The Windows system calls for enumerating / iterating / opening / updating the threads seem to be quite expensive.

Ideally, there would be a Window configuration option that allows you to replace the default/initial process / thread affinity with a user configurable mask.
This could be used to ensure that any new processes would never be scheduled on the same cores as the realtime audio threads.

## Legal
This utility is mostly pieced together from Microsoft reference / example code found on MSDN. It is public domain, i.e. do what you want but don't blame me in the (highly unlikely) event that something goes wrong.

The source code comes with a Visual Studio C++ 2019 (community edition) solution file, in case you want to build / modify the utility yourself.
