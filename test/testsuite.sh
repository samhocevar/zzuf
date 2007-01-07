#!/bin/sh

set -e

create()
{
    rm -f /tmp/zzuf-zero-$$
    dd if=/dev/zero of=/tmp/zzuf-zero-$$ bs=1024 count=32 2>/dev/null
    rm -f /tmp/zzuf-random-$$
    dd if=/dev/urandom of=/tmp/zzuf-random-$$ bs=1024 count=32 2>/dev/null
    rm -f /tmp/zzuf-text-$$
    strings </dev/urandom | dd bs=1024 count=32 of=/tmp/zzuf-text-$$ 2>/dev/null
    echo "" >> /tmp/zzuf-text-$$ # Make sure we have a newline at EOF
}

check()
{
    ZZOPTS="$1"
    CMD="$2"
    ALIAS="$3"
    echo -n " $(echo "$ALIAS .............." | cut -b1-18) "
    NEWMD5="$(eval "$ZZUF $ZZOPTS $CMD" 2>/dev/null | $MD5PROG | cut -b1-32)"
    if [ -z "$MD5" ]; then
        MD5="$NEWMD5"
        echo "$NEWMD5"
    elif [ "$NEWMD5" != "$MD5" ]; then
        OK=0
        echo "$NEWMD5 FAILED"
    else
        echo 'ok'
    fi
}

cleanup() {
    if [ "$FAILED" = 0 ]; then
        rm -f /tmp/zzuf-zero-$$
        rm -f /tmp/zzuf-random-$$
        rm -f /tmp/zzuf-text-$$
        echo "*** temporary files removed ***"
    else
        echo "*** files preserved ***"
        echo " /tmp/zzuf-zero-$$"
        echo " /tmp/zzuf-random-$$"
        echo " /tmp/zzuf-text-$$"
    fi
}

trap "echo ''; echo '*** ABORTED ***'; cleanup; exit 0" 1 2 15

seed=$((0$1))
ZZUF="$(dirname "$0")/../src/zzuf"
FDCAT="$(dirname "$0")/fdcat"
STREAMCAT="$(dirname "$0")/streamcat"
if md5sum /dev/null >/dev/null 2>&1; then
  MD5PROG=md5sum
elif md5 /dev/null >/dev/null 2>&1; then
  MD5PROG=md5
else
  echo "error: no md5 program found (tried: md5sum, md5)"
  exit 1
fi
if [ ! -f "$FDCAT" -o ! -f "$STREAMCAT" ]; then
  echo "error: test/fdcat or test/streamcat are missing"
fi
FAILED=0
TESTED=0

echo "*** running zzuf test suite ***"
echo "*** creating test files ***"
create
echo "*** using seed $seed ***"

for r in 0.000000 0.00001 0.0001 0.001 0.01 0.1 1.0 10.0; do
    for file in /tmp/zzuf-zero-$$ /tmp/zzuf-text-$$ /tmp/zzuf-random-$$; do
        ZZOPTS="-s $seed -r $r"
        case $file in
          *text*) ZZOPTS="$ZZOPTS -P '\n'" ;;
        esac
        echo "*** file $file, ratio $r ***"
        OK=1
        MD5=""
        check "$ZZOPTS" "cat $file" "cat"
        check "$ZZOPTS" "-i cat < $file" "|cat"
        case $file in
          *text*)
            # We don't include grep or sed when the input is not text, because
            # they put a newline at the end of their input if it was not there
            # initially. (Linux sed doesn't, but OS X sed does.)
            check "$ZZOPTS" "head -- -n 9999 $file" "head -n 9999"
            check "$ZZOPTS" "tail -- -n 9999 $file" "tail -n 9999"
            check "$ZZOPTS" "tail -- -n +1 $file" "tail -n +1"
            check "$ZZOPTS" "grep -- -a '' $file" "grep -a ''"
            check "$ZZOPTS" "sed -- -e n $file" "sed -e n"
            #check "$ZZOPTS" "cut -- -b1- $file" "cut -b1-"
            check "$ZZOPTS" "-i head -- -n 9999 < $file" "|head -n 9999"
            check "$ZZOPTS" "-i tail -- -n 9999 < $file" "|tail -n 9999"
            check "$ZZOPTS" "-i tail -- -n +1 < $file" "|tail -n +1"
            check "$ZZOPTS" "-i grep -- -a '' < $file" "|grep -a ''"
            check "$ZZOPTS" "-i sed -- -e n < $file" "|sed -e n"
            #check "$ZZOPTS" "-i cut -- -b1- < $file" "|cut -b1-"
            ;;
        esac
        check "$ZZOPTS" "dd bs=65536 if=$file" "dd(bs=65536)"
        check "$ZZOPTS" "dd bs=1111 if=$file" "dd(bs=1111)"
        check "$ZZOPTS" "dd bs=1024 if=$file" "dd(bs=1024)"
        check "$ZZOPTS" "dd bs=1 if=$file" "dd(bs=1)"
        check "$ZZOPTS" "$FDCAT $file" "fdcat"
        check "$ZZOPTS" "$STREAMCAT $file" "streamcat"
        if [ "$OK" != 1 ]; then
            echo "*** FAILED ***"
            FAILED=$(($FAILED + 1))
        fi
        TESTED=$(($TESTED + 1))
    done
done

if [ "$FAILED" != 0 ]; then
    echo "*** $FAILED tests failed out of $TESTED ***"
    cleanup
    exit 1
fi
echo "*** all $TESTED tests OK ***"

cleanup
exit 0

