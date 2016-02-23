# XIVPvP

An application for gathering Frontline and Wolves Den match details.

# Installing and using

- Download the latest [release](https://github.com/XIVPvP/XIVPvP/releases) and extract the contents to a folder. 
- Run XIVPvP.exe
- Play a match of Seal Rock or Wolves Den. After the match has ended, right click on the tray icon and select *View last match*

# Compiling

There is no makefile yet.

Build the resource file:

    windres xivpvp.rc -O coff -o xivpvp.res

Compile (MinGW):

    gcc -s -O2 -Iinclude xivpvp.c xivpvp.res -o amd64/XIVPvP.exe -Wall -lz -lWinDivert -lws2_32 -mwindows -Lamd64

# Notes

The code, while still a bit dirty, does the job. Pull requests are welcome.

There are still some issues with fragmented packets, which is my current focus to fix.

For any other bugs or feature requests, please open an issue.

# Changelog
- v1.43 - fix Wolves' Den capture
- v1.42 - fix bug "FFXIV not running" when a lot of TCP connections are opened.
- v1.41 - oopps, proper fix.
- v1.4 - fixed a crash when packets had 0 messages (?)
- v1.3 - implemented an update check on startup; allow only once instance
- v1.2 - fixed a bug where incomplete player data was submitted due to even more fragmentation!
- v1.1 - discovered a crash due to fragmented packets. This is a quick fix, need to find out why the data is getting corrupted and implement a proper fix that won't drop corrupted packets.
- v1.0 - initial release