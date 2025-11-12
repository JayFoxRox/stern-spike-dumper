# stern-spike-dumper

A tool to make a backup of your Stern Spike pinball machine EEPROMs and hardware fuses.
There's a chance that this will brick your CPU board. You've been warned.


## Building

1. Get https://musl.cc/arm-linux-musleabi-cross.tgz
2. Build:
    ```bash
    muslgcc=arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc
    $muslgcc main.c -static -no-pie -DSPIKE=1 -o stern-spike-1-dumper
    $muslgcc main.c -static -no-pie -DSPIKE=2 -o stern-spike-2-dumper
    ```


## Running

See some of the following how you can configure your machine for remote-access:

- https://pastebin.com/raw/RryUb8iC
- https://missionpinball.org/latest/hardware/spike/mpf-spike-bridge/
- https://missionpinball.org/latest/hardware/spike/connection/
- https://www.pinballinfo.com/community/threads/spike-debug-console.49678/


The script will dump the files into the current directory, so it's recommended to run it from /tmp/.
