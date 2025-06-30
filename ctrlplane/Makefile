SDE:=/home/netcom/bf-sde-9.13.2

ppv_egress_demo_marker: ppv_egress_demo_marker.cpp
	g++ -O3 -g3 -ggdb -std=c++14 -I$(SDE)/install/include/ -I m4 -Wl,--no-as-needed -L $(SDE)/install/lib/ -lbfutils -lpthread -ldriver $^ -o $@
# g++ -O3 -g3 -ggdb -std=c++14 -I$(SDE)/install/include/ -I m4 -Wl,--no-as-needed -L $(SDE)/install/lib/ -lbfutils -lbfsys -ldriver -lbf_switchd_lib -lpiall -lpifeproto -lpthread $^ -o $@

