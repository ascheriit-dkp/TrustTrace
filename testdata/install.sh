#!/bin/sh
set -eu
printf 'hello\n' > /tmp/trusttrace-demo
read -r value < /tmp/trusttrace-demo
rm /tmp/trusttrace-demo
