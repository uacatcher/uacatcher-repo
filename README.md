# UACatcher

```
         _      ___      _       _
 /\ /\  /_\    / __\__ _| |_ ___| |__   ___ _ __
/ / \ \//_\\  / /  / _` | __/ __| '_ \ / _ \ '__|
\ \_/ /  _  \/ /__| (_| | || (__| | | |  __/ |
 \___/\_/ \_/\____/\__,_|\__\___|_| |_|\___|_|

```

UACatcher is a static analysis tool that aims to find UAC (Use-After-Cleanup) bug in Linux kernel.

## How-to

Please refer to this [document](docs/GUIDE.md) for how to use UACatcher.

```
.
|-- docs  documentations
|-- emu   emulator code
`-- scripts  uacatcher major code
```

## Reference

https://www.computer.org/csdl/proceedings-article/sp/2023/933600b472/1Js0DZUDcyI

```
@inproceedings{ma2022top,
  title={When Top-down Meets Bottom-up: Detecting and Exploiting Use-After-Cleanup Bugs in Linux Kernel},
  author={Ma, Lin and Zhou, Duoming and Wu, Hanjie and Zhou, Yajin and Chang, Rui and Xiong, Hao and Wu, Lei and Ren, Kui},
  booktitle={2023 IEEE Symposium on Security and Privacy (SP)},
  pages={1472--1488},
  year={2022},
  organization={IEEE Computer Society}
}
```