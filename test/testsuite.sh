#!/bin/sh

ZZUF="$(dirname "$0")/../src/zzuf"

echo "Testing zzuf on itself:"
MD5_CAT=$($ZZUF cat $ZZUF | md5sum)
echo " - cat:          $MD5_CAT"
MD5_DD_1=$($ZZUF dd if=$ZZUF bs=1 2>/dev/null | md5sum)
echo " - dd(bs=1):     $MD5_DD_1"
MD5_DD_1024=$($ZZUF dd if=$ZZUF bs=1024 2>/dev/null | md5sum)
echo " - dd(bs=1024):  $MD5_DD_1024"

