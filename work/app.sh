#!/bin/bash
export PYTHONIOENCODING=utf-8
# usage: ./app.sh "addr<TAB>name<TAB>subsys<TAB>evidence" ...
for line in "$@"; do printf '%s\n' "$line" >> funcid_solo_batch1.tsv; done
wc -l < funcid_solo_batch1.tsv
