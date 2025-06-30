## PPV
p4-switch:~/mainrepo/QoS-TM/DT-Demo/ctrlplane
`sudo ./start.sh`
(should run in screen)

run ping for arp on traffic-gen:
` ping -c 5 192.168.40.4`

## Grafana
edge1:~/ppv/grafana
`docker compose up -d`

Runs on port 3000, can be accessed through ssh port forward or http://10.5.1.21:3000/d/FYk0tjXnk/desire6g
(default credentials admin/admin)

## Influx loader
edge1:~/ppv/grafana
`python3 loader.py`
(should run in screen)

## Pyperf sever and ping
edge1:~/ppv/pyperf
`./pyperf.py script_cmd "ping -I 192.168.40.4 192.168.40.51 | tee -a screenlogs/ping_f_classic"`
`./pyperf.py script_name_s.cc0*srv -ft GC0 -p 6000`

## Pyperf client
traffic-gen:~/ppv/pyperf
`./pyperf.py script_name_c.cc0_X_port30000*cli -ft GC0 -f 10 -p 6000 -B 20000`

## Pyperf
Can be managed with CLI menu
`./pyperf.py gui`

## IML
edge1:~/desire6g/mainrepo/IML/demo
see readme there
