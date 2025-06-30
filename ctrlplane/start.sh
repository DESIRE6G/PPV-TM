#!/bin/bash

echo "Kill any other control plane process..."

kill -9 `pgrep ppv_egress_demo`
kill -9 `pgrep bf_switch`
kill -9 `pgrep bfshell`
kill -9 `pgrep bfshell`

MY_DIR=$(pwd)

echo "Set the environment..."
export SDE_FOLDER=/home/netcom/bf-sde-9.13.2/
if [ -z ${SDE} ]; then
	        echo "SDE environment variable not set. Automatic config for $SDE_FOLDER"
		        SDE=$SDE_FOLDER
		else
			        echo "Using SDE folder: $SDE"
fi

echo "Using SDE folder: $SDE"

export SDE
cd $SDE
source $SDE/set_sde.bash

export LD_LIBRARY_PATH=$SDE/install/lib/
#mkfifo /tmp/bfshell.fifo
#(sleep 30 ; $SDE_FOLDER/run_bfshell.sh --no-status-srv -f /p4sde/port_config.txt < /tmp/bfshell.fifo ) &
#(sleep 25 ; $SDE/run_bfshell.sh --no-status-srv -f /p4sde/port_config.txt < /tmp/bfshell.fifo > /dev/null ) &
#(sleep 32 ; /home/admin/tools/run_pd_rpc.py --no-wait /home/efejfer/ppov_p4/ctrlplane/pd_config.py ) &
#(sleep 27 ; /p4sde/tools/run_pd_rpc.py --no-wait /home/efejfer/ppov_p4/ctrlplane/pd_config.py > /dev/null ) &

cd $MY_DIR
echo "Starting the control plane..."
./ppv_egress_demo_marker --install-dir $SDE/install --conf-file $SDE/build/p4-build/tofino/ppv_egress_demo_marker/ppv_egress_demo_marker/tofino/ppv_egress_demo_marker.conf --capacity 0.3

