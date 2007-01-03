#!/bin/sh

set -e

create()
{
    rm -f /tmp/zzuf-zero-$$
    dd if=/dev/zero of=/tmp/zzuf-zero-$$ bs=1024 count=32 2>/dev/null
    rm -f /tmp/zzuf-random-$$
    dd if=/dev/urandom of=/tmp/zzuf-random-$$ bs=1024 count=32 2>/dev/null
    rm -f /tmp/zzuf-text-$$
    strings /dev/urandom | dd bs=1024 count=32 of=/tmp/zzuf-text-$$ 2>/dev/null
}

check()
{
    SEED="$1"
    RATIO="$2"
    CMD="$3"
    ALIAS="$4"
    echo -n " $(echo "$ALIAS:              " | cut -b1-15)"
    NEWMD5="$(eval "$ZZUF -s $SEED -r $RATIO $CMD" 2>/dev/null | md5sum | cut -b1-32)"
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

cleanup() {
    if [ "$FAILED" = 0 ]; then
        rm -f /tmp/zzuf-zero-$$
        rm -f /tmp/zzuf-random-$$
        rm -f /tmp/zzuf-text-$$
        echo "Temporary files removed."
    else
        echo "Files preserved:"
        echo "  /tmp/zzuf-zero-$$"
        echo "  /tmp/zzuf-random-$$"
        echo "  /tmp/zzuf-text-$$"
    fi
}

trap "echo ''; echo ''; echo 'Aborted.'; cleanup; exit 0" 1 2 15

seed=$((0$1))
ZZUF="$(dirname "$0")/../src/zzuf"
FDCAT="$(dirname "$0")/fdcat"
STRAMCAT="$(dirname "$0")/streamcat"
FAILED=0
TESTED=0

echo "Creating test files"
create
echo "Using seed $seed"
echo ""

for file in /tmp/zzuf-zero-$$ /tmp/zzuf-text-$$ /tmp/zzuf-random-$$; do
    for r in 0.000000 0.00001 0.0001 0.001 0.01 0.1 1.0 10.0; do
        echo "Testing zzuf on $file, ratio $r:"
        OK=1
        MD5=""
        check $seed $r "cat $file" "cat"
        check $seed $r "-i cat < $file" "cat stdin"
        # We don't include grep in the testsuite because it puts a newline
        # at the end of its input if it was not there initially.
        #check $seed $r "grep -- -a \\'\\' $file" "grep -a"
        # We don't include sed in the testsuite because on OS X in also
        # puts a newline. Crap.
        #check $seed $r "-- sed -e n $file" "sed n"
        check $seed $r "dd bs=65536 if=$file" "dd(bs=65536)"
        check $seed $r "dd bs=1111 if=$file" "dd(bs=1111)"
        check $seed $r "dd bs=1024 if=$file" "dd(bs=1024)"
        check $seed $r "dd bs=1 if=$file" "dd(bs=1)"
        check $seed $r "$FDCAT $file" "fdcat"
        check $seed $r "$STRAMCAT $file" "streamcat"
        if [ "$OK" != 1 ]; then
            echo "*** FAILED ***"
            FAILED=$(($FAILED + 1))
        fi
        TESTED=$(($TESTED + 1))
        echo ""
    done
done

if [ "$FAILED" != 0 ]; then
    echo "$FAILED tests failed out of $TESTED."
    cleanup
    exit 1
fi
echo "All $TESTED tests OK."

cleanup
exit 0

