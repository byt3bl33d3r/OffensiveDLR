# Kukulkan

<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/YaxchilanDivineSerpent.jpg/170px-YaxchilanDivineSerpent.jpg" alt="Kukulkan"/>
</p>

## Description

This is basically a slimmed down version of [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY).

Kukulkan provides a C# DLL & EXE that embeds an IronPython engine allowing you to run IronPython scripts natively on Windows 10.

The Payload Server is used for C2: it hosts the needed assemblies, 'jobs' &  handles output.

C2 Comms are performed over HTTPS (server also supports HTTP2), everything is encrypted using AES-256, including the initial stage :).

The reasoning behind making this is to provide researches/red-teamers/pentesters a way of experimenting with the idea without having all the overhead of installing [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) which is not yet stable.

Additionally this is (i think?) 100% opsec safe, since the project provides .NET assemblies this can be used with other C2 platforms such as CobaltStrike.

## Usage:

```Usage: Kukulkan.exe <key> <IV> <URL>```


The ```Key``` & ```IV``` arguments are provided to you when you start the Payload Server


## Disclaimer 

I am by no means a crypto guru, if I implemented something wrong in the comms feel free to yell at me on Twitter or open an issue ticket (better yet a PR!).