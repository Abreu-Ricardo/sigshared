#!/bin/bash

ARCH=$1
#SPRIGHT_PATH="/mydata/spright/"
SIGSHARED_PATH="/mydata/sigshared/"

if [ -z "$ARCH" ] ; then
  #echo "Usage: $0 < s-spright | d-spright >"
  echo "Usage: $0 < sigshared >"
  exit 1
fi

if [ -z "$TMUX" ]; then
  if [ -n "`tmux ls | grep spright`" ]; then
    tmux kill-session -t spright
  fi
  tmux new-session -s spright -n demo "./set_tmux_master.sh $ARCH $SIGSHARED_PATH"
fi
