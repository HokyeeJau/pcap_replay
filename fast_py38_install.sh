#!/usr/bin/env bash 
#

action=$1
target=$2

function download(){
	echo "------- Start Fast Python3.8.5 Installation -------"
	cd /opt
	curl -O https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tgz
	yum install gcc openssl-devel bzip2-devel libffi-devel -y 
	tar -zxvf /opt/Python-3.8.5.tgz
	cd /opt/Python-3.8.5
	/opt/Python-3.8.5/configure --enable-optimizations
	cd /opt/Python-3.8.5 && make altinstall 

	echo "------- Change the Source -------"
	cd ~
	mkdir .pip 
	cd .pip 
	cp /opt/pcap_replay/pip.conf ~/.pip/pip.conf

	echo "------- Install Virtualenv -------"
	pip3.8 install virtualenv virtualenvwrapper

	echo "------- Clear Packages and Make Env -------"
	cd /opt 
	rm -rf /opt/Python-3.8.5
	rm -rf /opt/Python-3.8.5.tgz 
	virtualenv -p /usr/local/bin/python3.8 py3 


	echo "------- Download Libs ------- "
	/opt/py3/bin/pip3.8 install pyshark scapy pyyaml
	echo "please activate the sender using the following command:"
	echo "./fast_py38_install.sh activate"
}

function activate(){
  for i in $(seq 1 $1)
  do
    echo "------- Run PCAP Replay -------"
    nohup /opt/py3/bin/python -u /opt/pcap_replay/main.py > test.log 2>&1 &
    echo "Replaying!"
  done
}

function stop(){
  pids=`ps -ef | grep /opt/py3/bin/python | grep -v "grep" | awk '{print $2}'`
  echo "Current processes: $pids"

  for id in $pids
  do
    kill -9 $id
    echo "killed $id"
  done
}

function count(){
  pids=`ps -ef | grep /opt/py3/bin/python | grep -v "grep" | awk '{print $2}'`
  echo $pids
}

function usage(){
	echo 'Pcap Replay Handler'
	echo
	echo "Usage: "
	echo "	./fast_py38_install [COMMAND]"
	echo "	./fast_py38_install --help"
	echo "Commands: "
	echo "	download    Install Python Envr"
	echo "	activate    Start Replay"
	echo "	stop        Stop Replay"
	echo "	count       Count replay processes"
}

function main(){
	case "${action}" in
		download)
			download
			;;
		activate)
		  if [ ! $target ]; then
		    target=3
		  fi
		  activate $target
			;;
		count)
			count
			;;
		stop)
			stop
			;;
		--help)
			usage
			;;
		*)
      		echo -e "unknown COMMAND: '$action'"
      		echo -e "See './fast_py38_install --help' \n"
      		usage
      		;;
	esac
}

main
