#!/bin/sh
( sleep 25; /userconfig/repeater_up.sh ) >/userconfig/repeater_boot.log 2>&1 &
exit 0
