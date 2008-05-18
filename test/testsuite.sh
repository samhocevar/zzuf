#!/bin/sh

set -e

checkflip()
{
    r=$1
    expect=$2
    s2=$seed
    mib=20
    echo "*** $mib MiB of zeroes, ratio $r ***"
    echo " expected ....... $expect"
    rmax=-1
    rmin=-1
    rtot=0
    for x in 0 1 2 3 4 5 6 7 8 9; do
        ret=`dd if=/dev/zero bs=1048576 count=$mib 2>/dev/null | "$ZZUF" -s $s2 -r $r | "$ZZERO"`
        if [ "$rmax" = -1 -o "$ret" -gt "$rmax" ]; then rmax=$ret; fi
        if [ "$rmin" = -1 -o "$ret" -lt "$rmin" ]; then rmin=$ret; fi
        rtot=`expr $rtot + $ret || true`
        echo " try $x .......... $ret"
        s2=`expr $s2 + 1`
    done
    rmean=`expr '(' $rtot + 5 ')' / 10 || true`
    delta=`expr $rmean - $expect || true`
    if [ "$delta" -gt -5 -a "$delta" -lt 5 ]; then
        result="ok"
    elif [ $(($rmean * 8)) -lt $(($expect * 7)) \
               -o $(($rmean * 7)) -gt $(($expect * 8)) ]; then
        result="FAILED"
        FAILED=$(($FAILED + 1))
    else
        result="ok"
    fi
    TESTED=$(($TESTED + 1))
    echo " min/avg/max $rmin/$rmean/$rmax .......... $result"
}

checkutils()
{
    r=$1
    for type in 00 ff text random; do
        file="$DIR/file-$type"
        ZZOPTS="-s $seed -r $r"
        case $file in
          *text*) ZZOPTS="$ZZOPTS -P '\n'" ;;
        esac
        echo "*** file $file, ratio $r ***"
        REFMD5=""
        if [ $r = 0.0 -a $type = 00 ]; then
            check="bb7df04e1b0a2570657527a7e108ae23"
            echo "*** should be $check ***"
            check "$ZZOPTS" "< $file" "zzuf" "$check"
        else
            check "$ZZOPTS" "< $file" "zzuf"
        fi
        for n in 1 2 3; do
            check "$ZZOPTS" "$ZZCAT $n $file" "zzcat $n"
        done
        if [ "$STATIC_CAT" = "" ]; then
            check "$ZZOPTS" "cat $file" "cat"
            check "$ZZOPTS" "-i cat < $file" "|cat"
        fi
        if [ "$STATIC_DD" = "" ]; then
            check "$ZZOPTS" "dd bs=65536 if=$file" "dd(bs=65536)"
            check "$ZZOPTS" "dd bs=1111 if=$file" "dd(bs=1111)"
            check "$ZZOPTS" "dd bs=1024 if=$file" "dd(bs=1024)"
            check "$ZZOPTS" "dd bs=1 if=$file" "dd(bs=1)"
        fi
        case $file in
          *text*)
            # We don't include grep or sed when the input is not text, because
            # they put a newline at the end of their input if it was not there
            # initially. (Linux sed doesn't, but OS X sed does.)
            check "$ZZOPTS" "head -n 9999 $file" "head -n 9999"
            check "$ZZOPTS" "tail -n 9999 $file" "tail -n 9999"
            check "$ZZOPTS" "tail -n +1 $file" "tail -n +1"
            check "$ZZOPTS" "grep -a '' $file" "grep -a ''"
            check "$ZZOPTS" "sed -e n $file" "sed -e n"
            #check "$ZZOPTS" "cut -b1- $file" "cut -b1-"
            check "$ZZOPTS" "-i head -n 9999 < $file" "|head -n 9999"
            check "$ZZOPTS" "-i tail -n 9999 < $file" "|tail -n 9999"
            check "$ZZOPTS" "-i tail -n +1 < $file" "|tail -n +1"
            check "$ZZOPTS" "-i grep -a '' < $file" "|grep -a ''"
            check "$ZZOPTS" "-i sed -e n < $file" "|sed -e n"
            #check "$ZZOPTS" "-i cut -b1- < $file" "|cut -b1-"
            ;;
        esac
    done
}

check()
{
    ZZOPTS="$1"
    CMD="$2"
    ALIAS="$3"
    CHECK="$4"
    echo -n " $(echo "$ALIAS .............." | cut -b1-18) "
    MD5="$(eval "$ZZUF -m $ZZOPTS $CMD" 2>/dev/null | cut -f2 -d' ')"
    if [ -n "$CHECK" ]; then
        REFMD5="$CHECK"
    fi
    if [ -z "$REFMD5" ]; then
        REFMD5="$MD5"
        echo "$MD5"
    else
        TESTED=$(($TESTED + 1))
        if [ "$MD5" != "$REFMD5" ]; then
            FAILED=$(($FAILED + 1))
            echo "$MD5 FAILED"
        else
            echo 'ok'
        fi
    fi
}

DIR="$(dirname "$0")"
ZZUF="$DIR/../src/zzuf"
ZZCAT="$DIR/zzcat"
if [ ! -f "$ZZCAT" ]; then
  echo "error: test/zzcat is missing"
  exit 1
fi
ZZERO="$DIR/zzero"
if [ ! -f "$ZZERO" ]; then
  echo "error: test/zzero is missing"
  exit 1
fi
if file /bin/cat | grep -q 'statically linked'; then
  STATIC_CAT=1
fi
if file /bin/dd | grep -q 'statically linked'; then
  STATIC_DD=1
fi
FAILED=0
TESTED=0

if [ -z "$1" ]; then
  seed=$(date | $ZZUF -m 2>/dev/null | cut -f2 -d' ' | tr -d abcdef | cut -b1-8)
else
  seed="$1"
fi

echo "*** running zzuf test suite with seed $seed ***"

echo ""
echo "*** check #1: random number generator ***"
# if X flips are performed on N bits set to 0, the average number of bits
# set to 1 is: N / 2 * (1 - pow(1 - 2 / N, X)
checkflip 0.000000001 0
checkflip 0.00000001  1
checkflip 0.0000001  16
checkflip 0.000001  167
checkflip 0.00001  1677
checkflip 0.0001  16775
checkflip 0.001  167604
checkflip 0.01  1661055
checkflip 0.1  15205967

echo ""
echo "*** check #2: libc functions coverage ***"
checkutils 0.0
checkutils 0.000000001
checkutils 0.0000001
checkutils 0.00001
checkutils 0.001
checkutils 0.1
checkutils 10.0

echo ""
if [ "$FAILED" != 0 ]; then
    echo "*** $FAILED tests failed out of $TESTED ***"
    exit 1
fi
echo "*** all $TESTED tests OK ***"

exit 0

