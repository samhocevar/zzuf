#!/bin/sh

check()
{
    RATIO="$1"
    CMD="$2"
    ALIAS="$3"
    echo -n " $(echo "$ALIAS:              " | cut -b1-15)"
    NEWMD5="$($ZZUF -r $RATIO $CMD 2>/dev/null | md5sum | cut -b1-32)"
    if [ -z "$MD5" ]; then
        MD5="$NEWMD5"
        echo "$NEWMD5"
    elif [ "$NEWMD5" != "$MD5" ]; then
        OK=0
        echo "$NEWMD5"
    else
        echo ' ...'
    fi
}

ZZUF="$(dirname "$0")/../src/zzuf"
FAILED=0
TESTED=0

for file in /etc/passwd $ZZUF; do
    for r in 0.0 0.001 0.01 0.1 1; do
        echo "Testing zzuf on $file, ratio $r:"
        OK=1
        MD5=""
        check $r "cat $file" "cat"
# don't do grep, it adds a newline at EOF!
#        check $r "grep -- -a \\'\\' $file" "grep -a"
        check $r "sed n $file" "sed n"
        check $r "dd bs=1 if=$file" "dd(bs=1)"
        check $r "dd bs=1024 if=$file" "dd(bs=1024)"
        check $r "dd bs=1111 if=$file" "dd(bs=1111)"
        check $r "dd bs=65536 if=$file" "dd(bs=65536)"
        if [ "$OK" != 1 ]; then
            echo "*** FAILED ***"
            FAILED=$(($FAILED + 1))
        fi
        TESTED=$(($TESTED + 1))
        echo ""
    done
done

if [ "$FAILED" != 0 ]; then
    echo "$FAILED tests failed out of $TESTED"
    exit 1
fi
echo "All $TESTED tests OK."
exit 0

