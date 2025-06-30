#!/bin/bash

P4_APP='ppv_egress_demo_marker'
sudo kill -SIGUSR1 $(ps -C ${P4_APP} -o pid=)
