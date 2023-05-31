# Guide

## preparation

1. CodeQL

UACatcher requires [codeql](https://github.com/github/codeql) for analysis. Please install it and adopt this [patch](./field.patch) to support field-sensitive points-to.

> The CodeQL original points-to will confront bugs when handling same naming structure (which are common in Linux kernel)

2. Out directories

Please specify a output directory for UACatcher to place all related results. Let's say, `~/output` for now. (It's suggested to you prepare an output directory for each different kernel)


## prepare entire-kernel database

Using CodeQL to build database for Linux kernel is straightforward: you just need to pass you build commands. To build a allyesconfig database, you can do something like

```shell
cd <linux_dir>
make allyesconfig
codeql database create <datbase_dir> -s=<linux_dir> --language=cpp -j<N> --command="make all"
```

This will result in a HUGE database (like 30G+ size). Make sure you have enough disk and memory for storing such a big database.

You can manually turn off some options, like many option under [Kernel Hacking] to minimize your target.

## p1: layers preparing

The relvant code can be found at [here](../scripts/components/p1_layersprepare.py).

You can use the [runner](../scripts/runner.py) to run this component (or all other components).

```sh
python runner.py \
    --data ~/output \
    --kernelsrc <PATH TO KERNEL SRC> \
    --kerneldb <PATH TO KERNEL DB> \ 
    --codeqlcli <PATH TO CODEQL EXECUTABLE> \
    --codeqlrepo <PATH TO PATCHED CODEQL REPO> \
    --component p1
```

After this, you will find the (incomplete) layer descriptor file at `~/output/p1output`, and the created database at `~/output/database*`.

## p11: (one) layer preparing

Then we need to carefully complete the layer descriptor via p2 component.

Similarly, you can run the runner like below

```sh
python runner.py \
    --data ~/output \
    --inputdesc ~/output/p1output/[SOME JSON] \
    --codeqlcli <PATH TO CODEQL EXECUTABLE> \
    --codeqlrepo <PATH TO PATCHED CODEQL REPO> \
    --component p11
```

The output of this phase will be at `~/output/p11output` as json. Just check it out.

## p2: dPairs locating

After we have the complete layer descriptor (of course, and its database). We can start the analysis and locate the possible dPairs.

Run code like
```sh
python runner.py \
    --data ~/output \
    --inputdesc ~/output/p11output/[SOME JSON] \
    --codeqlcli <PATH TO CODEQL EXECUTABLE> \
    --codeqlrepo <PATH TO PATCHED CODEQL REPO> \
    --component p2
```

The output dPairs, as you might already guess, are placed at `~/output/p2output/`.

## p3: UAC detecting

UACatcher offer 3 choices for one to detect UAC from a possible dPair.
* manually
* lockset
* routine-switch

You can try them with code like

```
python runner.py \
    --data ~/output \
    --inputsum ~/output/p2output/[SOME LAYER]/[SOME SUMMARY]
    --algorithm [manual or lockset or routine-switch] \
    --codeqlcli <PATH TO CODEQL EXECUTABLE> \
    --codeqlrepo <PATH TO PATCHED CODEQL REPO> \
    --component p3
```

The final output, as you expect, is placed at `~/output/p3output`.

## more details

coming soon