#!/bin/sh

check()
{
    RATIO="$1"
    CMD="$2"
    $ZZUF -r $RATIO $CMD 2>/dev/null | md5sum
}

ZZUF="$(dirname "$0")/../src/zzuf"

for file in /etc/passwd $ZZUF; do
    for r in 0.0 0.001 0.01 0.1 1; do
        echo "Testing zzuf on $file, ratio $r:"
        echo "-  cat          $(check $r "cat $file")"
# don't do grep, it adds a newline at EOF!
#        echo "-  grep -a ''   $(check $r "grep -- -a \\'\\' $file")"
        echo "-  sed n        $(check $r "sed n $file")"
        echo "-  dd(bs=1)     $(check $r "dd bs=1 if=$file")"
        echo "-  dd(bs=1024)  $(check $r "dd bs=1024 if=$file")"
        echo "-  dd(bs=1111)  $(check $r "dd bs=1111 if=$file")"
        echo "-  dd(bs=65536) $(check $r "dd bs=65536 if=$file")"
    done
done

