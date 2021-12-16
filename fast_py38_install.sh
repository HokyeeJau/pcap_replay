#!/usr/bin/env bash 
#

action=$1

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
	echo "------- Run PCAP Replay -------"
	nohup /opt/py3/bin/python3 -u /opt/pcap_replay/main.py > test.log 2>&1 &
	echo "Replaying!"
}

function usage(){
	echo '流量重放安装脚本'
	echo 
	echo "Usage: "
	echo "	./fast_py38_install [COMMAND]"
	echo "	./fast_py38_install --help"
	echo "Commands: "
	echo "	download    安装py38环境与虚拟环境"
	echo "	activate    启动重放"
}

function main(){
	case "${action}" in 
		download)
			download
			;;
		activate)
			activate
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
