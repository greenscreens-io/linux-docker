#!/bin/bash

# (c) Copyright 2016, Green Screens Ltd.

DISK_REQUIREMENTS=0;
MEMORY_REQUIREMENTS=0;
CORE_REQUIREMENTS=0;

DIST="";
REV="";
KERNEL="";

#default exposed ports for available containers
SERVER_PORT=8080
SERVER_SSL_PORT=8443
SERVER_POLICY_PORT=8843

#start update mode - will download new Dockerfile and rebuild container
UPDATE="false";
FORCE="false"

#Install Nginx with simple routing config
NGINX="false";

#cluster dicovery mode; if true UDP used otherwise IP
#use IP only if running
MULTICAST="true";

#bind cluster to public address, only if multicast = false
PUBLIC="false";

#docker container memory, also set as max memory for Java
MEMORY="2048";

#docker login
USERNAME="";
PASSWORD="";

# where GS resources will be installed
INSTALL_PATH="/opt/greenscreens";

# network interface for docker isntance
LOCAL_INTERFACE="eth0";

##########################################
# Docker instance variables
##########################################
DOCKER_VOLUME="greenscreensVolume";
DOCKER_NETWORK="greenscreens-net";
DOCKER_CONTAINER_NAME="greenscreens";
DOCKER_IMAGE_VERSION="v1";
DOCKER_IMAGE_NAME="greenscreens/service";

##########################################
# Links to Dockerfiles
##########################################
DOCKERFILES_URL="https://raw.githubusercontent.com/greenscreens-io/linux-docker/master";
DOCKER_LATEST_SHA="https://www.dropbox.com/s/w1xn212hrg0kp0h/preflight.zip.sha1?dl=1";
DOCKER_BASE_FILE="Dockerfile-base.txt";
DOCKER_LATEST_FILE="Dockerfile-latest.txt";
DOCKER_LATEST_URL="${DOCKERFILES_URL}/${DOCKER_LATEST_FILE}";
DOCKER_BASE_URL="${DOCKERFILES_URL}/${DOCKER_BASE_FILE}";

##########################################
# Values to install GS as a system service
##########################################
SERVICE_DIR="/etc/systemd/system";
SERVICE_NAME="docker-greenscreens.service";
SERVICE_URL="${DOCKERFILES_URL}/${SERVICE_NAME}";

##########################################
# Values to install Nginx Sample config
##########################################
NGINX_SAMPLE="simple_nginx.txt";
NGINX_FILE="/etc/nginx/sites-available/default";
NGINX_URL="${DOCKERFILES_URL}/${NGINX_SAMPLE}";

##########################################
# Links t oget GS app token
##########################################
GS_ORIGIN="https://www.greenscreens.io";
GS_TOKEN="https://api.greenscreens.io/services/web/track?preflight=true";

##########################################
# bash parameters parser
##########################################

while [ "$1" != "" ]; do
	case $1 in

		-d | --dir )
			if [ "$2" != "" ]; then
				INSTALL_PATH=$2
				shift
			fi
		;;

		-p | --port )
			if [ "$2" != "" ]; then
				SERVER_PORT=$2
				shift
			fi
		;;

		-s | --ssl )
			if [ "$2" != "" ]; then
				SERVER_SSL_PORT=$2
				shift
			fi
		;;

		-i | --local-interface )
			if [ "$2" != "" ]; then
				LOCAL_INTERFACE=$2
				shift
			fi
		;;

		-m | --memory )
			if [ "$2" != "" ]; then
				MEMORY=$2
				shift
			fi
		;;

		-mc | --multicast )
			if [ "$2" != "" ]; then
				MULTICAST=$2
				shift
			fi
		;;

		-pi | --public-interface )
			if [ "$2" != "" ]; then
				PUBLIC=$2
				shift
			fi
		;;

		-f | --force )
			FORCE=true
			shift
		;;

		-u | --update )
			UPDATE=true
			shift
		;;

		-n | --nginx )
			NGINX=true
			shift
		;;

		-v | --volume )
			if [ "$2" != "" ]; then
				DOCKER_VOLUME=$2
				shift
			fi
		;;

		-\? | -h | --help )
			echo "  Usage $0 [PARAMETER] [[PARAMETER], ...]"
			echo "    Parameters:"
			echo "      -d, --dir                         install directory (default to $INSTALL_PATH)"
			echo "      -i, --public-interface            bind cluster engine for intercontainer discovery (default to $LOCAL_INTERFACE)"
			echo "      -m, --memory                      container max memory in MB (default to $MEMORY)"
			echo "      -mc, --multicast                  use cluster multicast discovery (true|false) (default to $MULTICAST)"
			echo "      -n, --nginx                       install nginx with simple routing to docker"
			echo "      -p, --port                        docker bind service port (default to $SERVER_PORT)"
			echo "      -s, --ssl                         docker bind service port SSL (default to $SERVER_SSL_PORT)"
			echo "      -pi, --public-interface           bind cluster to public interface (default to $PUBLIC)"
			echo "      -u, --update                      use to update existing components"
			echo "      -v, --volume                      docker configuration volume (default to $DOCKER_VOLUME)"
			echo "      -?, -h, --help                    this help"
			echo
			exit 0
		;;

		* )
			echo "Unknown parameter $1" 1>&2
			exit 0
		;;
	esac
	shift
done

#######################################
# Check if script is run as sudo
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
root_checking () {

	if [ ! "$( id -u )" -eq 0 ]; then
		echo "To perform this action you must be logged in with root rights"
		exit 0;
	fi

}

#######################################
# Convert string to lowercase
# Globals:
#   None
# Arguments:
#   String
# Returns:
#   None
#######################################
to_lowercase () {
	echo "$1" | sed "y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/"
}

#######################################
# Retrieve GS token during installation
# and save to token file in install loaction
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
get_token () {
	if [[ ! -f "${INSTALL_PATH}/token" ]]; then
		curl -Ls -o "${INSTALL_PATH}/token" -H "Origin: ${GS_ORIGIN}" "${GS_TOKEN}"
	fi
}

#######################################
# Detect Linux version
# Globals:
#   OS, DIST, REV, KERNEL
# Arguments:
#   None
# Returns:
#   None
#######################################
get_os_info () {

	OS=$(to_lowercase "$(uname)");

	if [ "${OS}" == "windowsnt" ]; then
		echo "Not supported OS";
		exit 0;
	elif [ "${OS}" == "darwin" ]; then
		echo "Not supported OS";
		exit 0;
	else
		OS=$(uname)

		if [ "${OS}" = "SunOS" ] ; then
			echo "Not supported OS";
			exit 0;
		elif [ "${OS}" = "AIX" ] ; then
			echo "Not supported OS";
			exit 0;
		elif [ "${OS}" = "Linux" ] ; then
			MACH=`uname -m`

			if [ "${MACH}" != "x86_64" ]; then
				echo "Currently only supports 64bit OS's";
				exit 0;
			fi

			KERNEL=$(uname -r)

			if [ -f /etc/redhat-release ] ; then
				DIST=$(cat /etc/redhat-release |sed s/\ release.*//)
				REV=$(cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//)
			elif [ -f /etc/SuSE-release ] ; then
				REV=$(cat /etc/os-release  | grep '^VERSION_ID' | awk -F= '{ print $2 }' | sed -e 's/^"//' -e 's/"$//')
				DIST='SuSe'
			elif [ -f /etc/debian_version ] ; then
				REV=$(cat /etc/debian_version)
				DIST='Debian'
				if [ -f /etc/lsb-release ] ; then
					DIST=$(cat /etc/lsb-release | grep '^DISTRIB_ID' | awk -F= '{ print $2 }')
					REV=$(cat /etc/lsb-release | grep '^DISTRIB_RELEASE' | awk -F= '{ print $2 }')
				elif [[ -f /etc/lsb_release ]]; then
					DIST=$(lsb_release -a 2>&1 | grep 'Distributor ID:' | awk -F ":" '{print $2 }')
					REV=$(lsb_release -a 2>&1 | grep 'Release:' | awk -F ":" '{print $2 }')
				fi
			elif [ -f /etc/os-release ] ; then
				if [ -f /etc/lsb-release ] ; then
					DIST='ChromeOS'
					REV=$(cat /etc/lsb-release | grep '^CHROMEOS_RELEASE_VERSION' | awk -F= '{ print $2 }')
					if [[ -z ${REV} ]]; then
						REV=$(cat /etc/os-release | grep '^VERSION_ID' | awk -F= '{ print $2 }' | sed -e 's/^"//' -e 's/"$//')
						DIST=$(cat /etc/os-release | grep '^ID' | awk -F= '{ print $2 }' | sed -e 's/^"//' -e 's/"$//')
					fi
				else
					REV=$(cat /etc/os-release | grep '^VERSION_ID' | awk -F= '{ print $2 }' | sed -e 's/^"//' -e 's/"$//')
					DIST=$(cat /etc/os-release | grep '^ID_LIKE' | awk -F= '{ print $2 }' | sed -e 's/^"//' -e 's/"$//')
				fi
			fi
		fi
	fi
}

#######################################
# Check if OS kernel is supported
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
check_os_info () {

	echo "Kernel: ${KERNEL}";
	echo "Revision: ${REV}";
	echo "Distribution: ${DIST}";

	if [[ -z "$KERNEL" || -z "$DIST" || -z "$REV" ]]; then
		echo "Not supported OS";
		exit 0;
	fi
}

#######################################
# Detect if Linux Kernel is supported
# Globals:
#   KERNEL
# Arguments:
#   None
# Returns:
#   None
#######################################
check_kernel () {

	local MIN_NUM_ARR=(3 10 0);
	local CUR_NUM_ARR=();

	CUR_STR_ARR=$(echo "$KERNEL" | grep -Po "[0-9]+\.[0-9]+\.[0-9]+" | tr "." " ");
	for CUR_STR_ITEM in $CUR_STR_ARR
	do
		CUR_NUM_ARR=("${CUR_NUM_ARR[@]}" "$CUR_STR_ITEM")
	done

	local INDEX=0;

	while [[ $INDEX -lt 3 ]]; do
		if [ "${CUR_NUM_ARR[INDEX]}" -lt "${MIN_NUM_ARR[INDEX]}" ]; then
			echo "Not supported OS Kernel"
			exit 0;
		elif [ "${CUR_NUM_ARR[INDEX]}" -gt "${MIN_NUM_ARR[INDEX]}" ]; then
			INDEX=3
		fi
		(( INDEX++ ))
	done
}

#######################################
# Check if hardware featrues are sufficient
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
check_hardware () {

	local TOTAL_MEMORY=0;
	local CPU_CORES_NUMBER=0;
	local AVAILABLE_DISK_SPACE=0;

	AVAILABLE_DISK_SPACE=$(sudo df -m /  | tail -1 | awk '{ print $4 }');

	if [ "${AVAILABLE_DISK_SPACE}" -lt "${DISK_REQUIREMENTS}" ]; then
		echo "Minimal requirements are not met: need at least $DISK_REQUIREMENTS MB of free HDD space"
		exit 0;
	fi

	TOTAL_MEMORY=$(free -m | grep -oP '\d+' | head -n 1);

	if [ "${TOTAL_MEMORY}" -lt "${MEMORY_REQUIREMENTS}" ]; then
		echo "Minimal requirements are not met: need at least $MEMORY_REQUIREMENTS MB of RAM"
		exit 0;
	fi

	CPU_CORES_NUMBER=$(cat /proc/cpuinfo | grep processor | wc -l);

	if [ "${CPU_CORES_NUMBER}" -lt "${CORE_REQUIREMENTS}" ]; then
		echo "The system does not meet the minimal hardware requirements. CPU with at least $CORE_REQUIREMENTS cores is required"
		exit 0;
	fi
}

#######################################
# Check if reuired command is exist in Linux
# Globals:
#   None
# Arguments:
#   String
# Returns:
#   None
#######################################
command_exists () {
	type "$1" &> /dev/null;
}

#######################################
# Check if file exist in Linux
# Globals:
#   None
# Arguments:
#   String
# Returns:
#   None
#######################################
file_exists () {

	if [ -z "$1" ]; then
		echo "File path is empty for $1"
		exit 0;
	fi

	if [ -f "$1" ]; then
		return 0; #true
	else
		return 1; #false
	fi
}

#######################################
# Check if directory exist in Linux
# Globals:
#   None
# Arguments:
#   String
# Returns:
#   None
#######################################
directory_exists () {

	if [ -z "$1" ]; then
		echo "File path is empty for $1"
		exit 0;
	fi

	if [ -d "$1" ]; then
		return 0; #true
	else
		return 1; #false
	fi
}

#######################################
# Find Linux public interface
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   String - IP address
#######################################
get_public_interface () {

	local IPADDR="";

	IPADDR=$(curl -Ls ipinfo.io/ip);

	if [ -z "$IPADDR" ]; then
		IPADDR=$(curl -Ls http://whatismyip.akamai.com)
	fi

	if [ -z "$IPADDR" ]; then
		IPADDR=$(curl -Ls ipecho.net/plain)
	fi

	if [ -z "$IPADDR" ]; then
		IPADDR=$(curl -Ls checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//' )
	fi

	if [ -z "$IPADDR" ]; then
		if command_exists dig ; then
			IPADDR=$(dig +short myip.opendns.com @resolver1.opendns.com)
		fi
	fi

	if [[ $IPADDR =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "$IPADDR"
	fi

}

#######################################
# Find Linux local interface
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   String - IP address
#######################################
get_local_interface () {

	local IPADDR="";

	if [ "${DIST}" == "SuSe" ] || [ "${DIST}" == "suse" ]; then
		IPADDR=$(ip a | grep -A 1 'eth0' | grep -A 0 'inet' | tail -1 |awk '{print $2;}' | sed 's/\///');
	else
		IPADDR=$(ifconfig | grep -A 1 "$LOCAL_INTERFACE" | tail -1 | awk '{print $2;}' |  sed 's/addr://');
	fi

	if [ -z "$IPADDR" ]; then
		IPADDR=$(hostname -I | awk '{print $1;}');
	fi

	echo "$IPADDR";

}

#######################################
# Instal lsudo command if possible
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
install_sudo () {

	if [ ! "${DIST}" == "ChromeOS" ]; then
	    return 0;
	fi

	if command_exists sudo ; then
		return 0;
	fi

	if command_exists apt-get; then
		apt-get install sudo
	elif command_exists yum; then
		yum install sudo
	fi

	if ! command_exists sudo; then
		echo "Command sudo not found!!!"
		exit 0;
	fi
}

#######################################
# Install hostname, used to detect IP's
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
install_hostname () {

	if command_exists hostname ; then
		return 0;
	fi

	if command_exists apt-get; then
		apt-get install hostname
	elif command_exists yum; then
		yum install hostname
	fi

	if ! command_exists hostname; then
		echo "Command hostname not found!!!"
		exit 0;
	fi
}

#######################################
# Setup Docker as sudoer to be used
# later without sudo command
# Globals:
#   DIST, USER
# Arguments:
#   None
# Returns:
#   None
#######################################
docker_sudoer () {

	if [ ! "${DIST}" == "ChromeOS" ]; then
		return 0;
	fi

	sudo groupadd docker
	#sudo usermod -aG docker ${USER}
	sudo gpasswd -a "${USER}" docker

	echo "Verifying Docker service...wait"

	local RUNNING=0
	RUNNING=$(check_service "docker")

	if [[ -z $RUNNING ]]; then
		RUNNING=0;
		sudo service docker start;
		sleep 5;
	fi

	while [[ -z $RUNNING ]]
	do
		sleep 5;
		RUNNING=$(check_service "docker");
	done

	echo "Verifying Docker service...OK"
}

#######################################
# Check Docker installed version
# Globals:
#   DIST
# Arguments:
#   None
# Returns:
#   String true or false
#          to indicate update is needed
#######################################
check_docker_version () {

	if [ ! "${DIST}" == "ChromeOS" ]; then
		return 0;
	fi

	echo "Verifying Docker version..."

	local MIN_NUM_ARR=(1 10 0);
	local CUR_NUM_ARR=();

	CUR_STR_ARR=$(docker -v | grep -Po "[0-9]+\.[0-9]+\.[0-9]+" | tr "." " ");
	for CUR_STR_ITEM in $CUR_STR_ARR
	do
		CUR_NUM_ARR=("${CUR_NUM_ARR[@]}" "$CUR_STR_ITEM")
	done

	local NEED_UPDATE="false"
	local INDEX=0;

	while [[ $INDEX -lt 3 ]]; do
		if [ "${CUR_NUM_ARR[INDEX]}" -lt "${MIN_NUM_ARR[INDEX]}" ]; then
			NEED_UPDATE="true"
			INDEX=3
		elif [ "${CUR_NUM_ARR[INDEX]}" -gt "${MIN_NUM_ARR[INDEX]}" ]; then
			INDEX=3
		fi
		(( INDEX++ ))
	done

	echo "$NEED_UPDATE"
}

#######################################
# Check if Docker is installed
# It will install / reinstall Docker
# if does not exist or version is to low
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
check_docker () {

	echo "Checking if Docker is installed..."

	if command_exists docker ; then
		local NEED_UPDATE=""
		NEED_UPDATE=$(check_docker_version);

		if [ "$NEED_UPDATE" == "true" ]; then
			uninstall_docker
			install_docker
		fi
	else
		install_docker
	fi
}

#######################################
# Uninstall Docker
# Globals:
#   DIST
# Arguments:
#   None
# Returns:
#   None
#######################################
uninstall_docker () {

	echo "Uninstalling old Docker version...";

	if [ "${DIST}" == "Ubuntu" ] || [ "${DIST}" == "Debian" ]; then

		sudo apt-get -y autoremove --purge docker-engine

	elif [[ "${DIST}" == CentOS* ]] || [ "${DIST}" == "Red Hat Enterprise Linux Server" ]; then

		sudo yum -y remove docker-engine.x86_64

	elif [ "${DIST}" == "SuSe" ] || [ "${DIST}" == "suse" ]; then

		sudo zypper rm -y docker

	elif [ "${DIST}" == "Fedora" ]; then

		sudo dnf -y remove docker-engine.x86_64

	else
		echo "Not supported OS"
		exit 0;
	fi
}

#######################################
# Install Docker into Linux
# Globals:
#   DIST
# Arguments:
#   None
# Returns:
#   None
#######################################
install_docker () {

	echo "Installing new Docker version..."

	if [ "${DIST}" == "Ubuntu" ] || [ "${DIST}" == "Debian" ]; then

		sudo apt-get -y update
		sudo apt-get -y -q install curl
		sudo curl -sSL https://get.docker.com/ | sh

	elif [[ "${DIST}" == CentOS* ]] || [[ "${DIST}" == *"Red Hat"* ]]; then

		sudo yum -y update
		sudo yum -y install curl
		sudo curl -fsSL https://get.docker.com/ | sh
		sudo service docker start
		sudo chkconfig docker on

	elif [ "${DIST}" == "SuSe" ] || [ "${DIST}" == "suse" ]; then

		sudo zypper in -y docker
		sudo systemctl start docker
		sudo systemctl enable docker

	elif [ "${DIST}" == "Fedora" ]; then

		sudo dnf -y update
		sudo yum -y update
		sudo yum -y install curl
		sudo curl -fsSL https://get.docker.com/ | sh
		sudo systemctl start docker
		sudo systemctl enable docker

	else
		echo "Not supported OS for Docker"
		exit 0;
	fi

	if ! command_exists docker ; then
		echo "Error while installing Docker"
		exit 0;
	fi
}

#######################################
# Install NginX
# Globals:
#   DIST
# Arguments:
#   None
# Returns:
#   None
#######################################
install_nginx () {

	if [ ! "$NGINX" == "true" ]; then
		return 0;
	fi

	if which nginx > /dev/null 2>&1; then
		echo "Nginx is already installed!"
		return 0;
	fi

	echo ""
	echo "Installing nginx service..."

	if [ "${DIST}" == "Ubuntu" ] || [ "${DIST}" == "Debian" ]; then

		sudo apt -y update
		sudo apt -y -q install nginx

	elif [[ "${DIST}" == CentOS* ]] || [ "${DIST}" == "Red Hat Enterprise Linux Server" ]; then

		sudo yum -y update
		sudo yum -y install nginx

	elif [ "${DIST}" == "SuSe" ] || [ "${DIST}" == "suse" ]; then

		sudo zypper in -y nginx

	elif [ "${DIST}" == "Fedora" ]; then

		sudo dnf -y update
		sudo yum -y update
		sudo yum -y install nginx

	else
		echo "Not supported OS for Docker"
		exit 0;
	fi

}

#######################################
# Configure Nginx PORT to Docker instance
# Globals:
#   DIST, SERVER_PORT,
#   NGINX_URL, NGINX_FILE
# Arguments:
#   None
# Returns:
#   None
#######################################
configure_nginx () {

	if [ ! "$NGINX" == "true" ]; then
		return 0;
	fi

	if ps -ae | grep nginx > /dev/null 2>&1; then
		echo "Nginx is already running!"
		return 0;
	fi

	local FILE=$NGINX_FILE

	if [ "${DIST}" == "SuSe" ] || [ "${DIST}" == "suse" ]; then
		echo "Setting nginx config dir..."
		FILE="/etc/nginx/conf.d/default.conf";
	fi

	sudo curl -Lo "${FILE}" "$NGINX_URL";
	sudo sed -i "s/GS_PORT/$SERVER_PORT/g" $FILE

	echo -e "Restarting nginx ...\c"
		if command_exists service ; then
 			sudo service nginx restart
			echo "OK"
		elif command_exists systemctl ; then
			sudo systemctl restart nginx
			echo "OK"
		else
			echo "WARNING: Nginx not restarted!"
		fi

}

#######################################
# Configure Nginx with simple config,
# but only if Nginx is not running
# Globals:
#   NGINX
# Arguments:
#   None
# Returns:
#   None
#######################################
setup_nginx () {

	if [ ! "$NGINX" == "true" ]; then
		return 0;
	fi

	install_nginx
	configure_nginx
}

## Green Screens Installation segment

#######################################
# Uninstall GS Docker instances
# by removing all images
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
uninstall () {
	sudo systemctl stop docker-greenscreens.service
	sudo systemctl disable docker-greenscreens.service
	sudo docker stop greenscreens
	sudo docker rm greenscreens
		sudo docker rmi greenscreens/service:v1
	sudo docker system prune
}

#######################################
# Install Docker instance as a system service
# Globals:
#   UPDATE, SERVICE_DIR, SERVICE_NAME, SERVICE_URL
# Arguments:
#   None
# Returns:
#   None
#######################################
install_system_service () {

	if [ "$UPDATE" == "true" ]; then
		return 0;
	fi

	directory_exists "${SERVICE_DIR}";

	if [[  $? -ne 0  ]]; then
		echo "Systemd service not installed...skip";
		return 0;
	fi

	sudo curl -sLo "${SERVICE_DIR}/${SERVICE_NAME}" "$SERVICE_URL";

	file_exists "${SERVICE_DIR}/${SERVICE_NAME}";

	if [[  $? -ne 0  ]]; then
		echo "WARN: Green Screens autostart service not installed";
	else
		sudo systemctl daemon-reload
		sudo systemctl enable docker-greenscreens
		sudo systemctl start docker-greenscreens

		echo " ";
		echo "Systemd service installed.";
		echo " ";
		echo "To control instance use:";
		echo "  sudo systemctl COMMAND[start|strop|enable|disable|status] docker-greenscreens";
		echo " ";
	fi

}

#######################################
# Setup Docker Login
# Globals:
#   USERNAME, PASSWORD
# Arguments:
#   None
# Returns:
#   None
#######################################
docker_login () {
	if [[ -n "${USERNAME}" && -n "${PASSWORD}" ]]; then
		sudo docker login -u "${USERNAME}" -p "${PASSWORD}"
	fi
}

#######################################
# Find Docker instance ID by given instance name
# Globals:
#   None
# Arguments:
#   String - container name
# Returns:
#   String - contaienr ID
#######################################
get_container_id () {

	local CONTAINER_NAME=$1;

	if [[ -z ${CONTAINER_NAME} ]]; then
		echo "ERROR: Empty container name!"
		exit 0;
	fi

	local CONTAINER_ID="";
	local CONTAINER_EXIST=0;

	CONTAINER_EXIST=$(sudo docker ps -a | awk '{print $NF}' | grep -x "${CONTAINER_NAME}");

	if [[ -n ${CONTAINER_EXIST} ]]; then
		CONTAINER_ID=$(sudo docker inspect --format='{{.Id}}' "${CONTAINER_NAME}");
	fi

	echo "$CONTAINER_ID"
}

#######################################
# Create Docker instance network config
# Globals:
#   DOCKER_NETWORK
# Arguments:
#   None
# Returns:
#   None
#######################################
create_network () {

	echo "Verifying existence of network configuration...$DOCKER_NETWORK"

	local EXIST=0

	EXIST=$(sudo docker network ls | awk '{print $2;}' | grep -x "${DOCKER_NETWORK}");

	if [[ -z $EXIST ]]; then
		echo "Creating network configuration...$DOCKER_NETWORK";
		sudo docker network create --driver bridge "${DOCKER_NETWORK}";
	fi

	EXIST=$(sudo docker network ls | awk '{print $2;}' | grep -x "${DOCKER_NETWORK}");

	if [[ -z $EXIST ]]; then
		echo "Error while creating $DOCKER_NETWORK network";
		exit 0;
	else
		echo "Create network configuration ($DOCKER_NETWORK)...OK";
	fi

}

#######################################
# Install Docker instance Named Volume
# used fro savin product settings and
# to keep them after instance teardown
# Globals:
#   DOCKER_VOLUME
# Arguments:
#   None
# Returns:
#   None
#######################################
create_volume () {

	echo "Verifying existence of volume configuration...$DOCKER_VOLUME"

	local EXIST=0;

	EXIST=$(sudo docker volume ls | awk '{print $2;}' | grep -x "$DOCKER_VOLUME");

	if [[ -z $EXIST ]]; then
		echo "Creating configuration volume...$DOCKER_VOLUME"
		sudo docker volume create --name "$DOCKER_VOLUME"
	fi

	EXIST=$(sudo docker volume ls | awk '{print $2;}' | grep -x "$DOCKER_VOLUME");

	if [[ -z $EXIST ]]; then
		echo "Error while creating volume...$DOCKER_VOLUME"
		exit 0;
	else
		echo "Create configuration volume ($DOCKER_VOLUME)...OK"
	fi
}

#######################################
# Remove GS Docker live instance
# Globals:
#   CONTAINER_NAME
# Arguments:
#   None
# Returns:
#   None
#######################################
remove_container () {

	echo "Removing docker container..."

	local CONTAINER_NAME=$1;

	if [[ -z ${CONTAINER_NAME} ]]; then
		echo "Empty container name"
		exit 0;
	fi

	echo "Stop container: $CONTAINER_NAME"
	sudo docker stop "${CONTAINER_NAME}";

	echo "Remove container: $CONTAINER_NAME"
	sudo docker rm -f "${CONTAINER_NAME}";

	sleep 10 #Hack for SuSe: exception "Error response from daemon: devmapper: Unknown device xxx"

	echo "Check removed container: $CONTAINER_NAME"
	local CONTAINER_ID=0;
	CONTAINER_ID=$(get_container_id "$CONTAINER_NAME");

	if [[ -n ${CONTAINER_ID} ]]; then
		echo "Try again remove ${CONTAINER_NAME}"
		remove_container "${CONTAINER_NAME}"
	else
		echo "Removing docker container ($CONTAINER_NAME)...OK"
	fi
}

#######################################
# Download Dockerfile used to build images
# Globals:
#   INSTALL_PATH, DOCKER_LATEST_FILE,
#   DOCKER_BASE_FILE
# Arguments:
#   None
# Returns:
#   None
#######################################
download_dockerfile () {

	echo "Downloading Dockerfile scripts to...$INSTALL_PATH"

	if [[ ! -d "${INSTALL_PATH}" ]]; then
		echo "Creating dirctory ${INSTALL_PATH}"
		sudo mkdir "${INSTALL_PATH}"
	fi

	echo "Updating Dockerfile with new version"

	if [[ ! -f "${INSTALL_PATH}/${DOCKER_LATEST_FILE}" ]]; then
		sudo rm "${INSTALL_PATH}/${DOCKER_LATEST_FILE}"
	fi

	if [[ ! -f "${INSTALL_PATH}/${DOCKER_BASE_FILE}" ]]; then
		sudo rm "${INSTALL_PATH}/${DOCKER_BASE_FILE}"
	fi

	sudo curl -sLo "${INSTALL_PATH}/${DOCKER_LATEST_FILE}" "${DOCKER_LATEST_URL}"
	sudo curl -sLo "${INSTALL_PATH}/${DOCKER_BASE_FILE}" "${DOCKER_BASE_URL}"
}

#######################################
# Check if Docker instance is active
# Globals:
#   None
# Arguments:
#   String - container name
# Returns:
#   String
######################################
container_active () {

	if [[ $# -lt 1 ]]; then
		echo "Invalid number of parameters";
		exit 0;
	fi

	local EXIST=0;
	EXIST=$(docker ps -f name="$1" | grep -w "$1");
	echo "$EXIST";
}

#######################################
# Check if Docker image exist
# Globals:
#   None
# Arguments:
#   String - image name
#   String - image tag
# Returns:
#   String
#######################################
image_exists () {

	if [[ $# -lt 2 ]]; then
		echo "Invalid number of parameters";
		exit 0;
	fi

	local EXIST=0;
	EXIST=$(sudo docker images | awk '{print $1,$2;}' | grep -x "$1 $2");
	echo "$EXIST";
}

#######################################
# Install Docker instance as a system service
# Globals:
#   DOCKER_IMAGE_NAME, INSTALL_PATH,
#   DOCKER_BASE_FILE, DOCKER_LATEST_FILE,
#   DOCKER_IMAGE_VERSION, DOCKER_IMAGE_NAME
# Arguments:
#   None
# Returns:
#   None
#######################################
install_image () {

	echo "Installing docker images..."

	local EXIST=0;
	EXIST=$(image_exists "${DOCKER_IMAGE_NAME}" "base");

	if [[ -z ${EXIST} ]]; then
		echo "Building base image...";
		sudo docker build -f "${INSTALL_PATH}/$DOCKER_BASE_FILE" . -t "${DOCKER_IMAGE_NAME}:base";
	else
		echo "Base image exist (${DOCKER_IMAGE_NAME}:base)...skip";
	fi

	EXIST=$(image_exists "${DOCKER_IMAGE_NAME}" "${DOCKER_IMAGE_VERSION}");

	if [[ -z ${EXIST} ]]; then
		echo "Building service image...";
		sudo docker build -f "${INSTALL_PATH}/$DOCKER_LATEST_FILE" . -t "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}";
	else
		echo "Service image exist (${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION})...skip";
		return 0;
	fi

	sleep 3;

	echo "Verify building service image (${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION})...";

	EXIST=$(image_exists "${DOCKER_IMAGE_NAME}" "${DOCKER_IMAGE_VERSION}");

	if [[ -z ${EXIST} ]]; then
		echo "Build service image failed: ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}"
		exit 0;
	else
		echo "Verify building service image (${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION})...OK";
	fi

	update_hash
}

#######################################
# Remove Docker image
# Globals:
#   DOCKER_IMAGE_NAME, DOCKER_IMAGE_VERSION
# Arguments:
#   None
# Returns:
#   None
#######################################
remove_image () {

	echo "Removing docker image...${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}"

	local EXIST=0;
	EXIST=$(image_exists "${DOCKER_IMAGE_NAME}" "${DOCKER_IMAGE_VERSION}");

	if [[ -n ${EXIST} ]]; then
		sudo docker rmi "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}"
	fi

	sleep 3

	EXIST=$(image_exists "${DOCKER_IMAGE_NAME}" "${DOCKER_IMAGE_VERSION}");

	if [[ -n ${EXIST} ]]; then
		echo "Error removing image ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}";
		exit 0;
	else
		echo "Removing docker image (${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION})...OK"
	fi
}

#######################################
# Check if new GS update file exist
# Compares local last hash and has from url
# Globals:
#   INSTALL_PATH, DOCKER_LATEST_SHA,
# Arguments:
#   None
# Returns:
#   Number - Return code 0 if no update
#######################################
update_exist () {

	local HASH_URL=$DOCKER_LATEST_SHA
	local HASH_PATH=$INSTALL_PATH
	local HASH_FILE=0;
	local NEW_HASH=0;
	local OLD_HASH=""

	echo "Checking update hashes...${HASH_URL}"

	HASH_FILE=${HASH_PATH}/data.txt
	NEW_HASH=$(curl -sL "${HASH_URL}"  | tail -l | awk '{ print $1 }' | sed 's/\/\///' |  tr -d '\n')

	if [ -f "$HASH_FILE" ]; then
		OLD_HASH=$(cat "${HASH_FILE}")
	fi

	echo "New hash ${NEW_HASH}"
	echo "Old hash ${OLD_HASH}"

	if [ "$OLD_HASH" == "$NEW_HASH" ]; then
		if [ "$FORCE" == "false" ]; then
			echo "INFO: No new updates!!!"
			return 0;
		else
			echo "WARN: Forced update requested....";
			return 1;
		fi
	else
		echo "INFO: New updates available";
		return 1;
	fi
}

#######################################
# Update update hash to local file
# for future update checks
# Globals:
#   INSTALL_PATH, DOCKER_LATEST_SHA
# Arguments:
#   None
# Returns:
#   None
#######################################
update_hash () {

	local HASH_URL=$DOCKER_LATEST_SHA
	local HASH_PATH=$INSTALL_PATH
	local HASH_FILE=0;
	local NEW_HASH=0;

	HASH_FILE=${HASH_PATH}/data.txt
	NEW_HASH=$(curl -sL "${HASH_URL}"  | tail -l | awk '{ print $1 }' | sed 's/\/\///' |  tr -d '\n')

	echo "Save new update hash ${NEW_HASH} after successful update to ${HASH_FILE}"
	sudo touch "$HASH_FILE"
	echo "${NEW_HASH}" > "$HASH_FILE"
}

#######################################
# Update GS applciation
# Globals:
#   UPDATE, DOCKER_CONTAINER_NAME
# Arguments:
#   None
# Returns:
#   None
#######################################
update_server () {

	if [ ! "$UPDATE" == "true" ]; then
		return 0;
	fi

	# check if there is a new update
	update_exist

	if [[ $? -eq 0 ]]; then
		return 0;
	fi

	echo "Stopping Green Screens Service...$DOCKER_CONTAINER_NAME"
	sudo systemctl stop docker-greenscreens.service

	echo "Updating Green Screens Service...$DOCKER_CONTAINER_NAME"

	local SERVER_ID=0;
	SERVER_ID=$(get_container_id "$DOCKER_CONTAINER_NAME");

	if [[ -n "$SERVER_ID" ]]; then
		remove_container "${DOCKER_CONTAINER_NAME}"
	fi

	remove_image
	install_image

	echo "Starting Green Screens Service...$DOCKER_CONTAINER_NAME"
	sudo systemctl start docker-greenscreens.service

}

#######################################
# Update Docker volume permissions from
# container user so that GS serve might
# have write access to this location
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
update_permissions () {

	echo "Updating volume permissions..."

	local VOLUME_PATH=0;
	local USER_ID=0;

	VOLUME_PATH=$(sudo docker inspect greenscreens | grep Source | sed 's/ //g' | sed 's/"Source":"//g' | sed 's/",//g');
	USER_ID=$(sudo docker exec -it --user 0 greenscreens id -u jboss | sed 's/\r//g');

	echo "Volume: $VOLUME_PATH"
	echo "UID: $USER_ID"

	# set groupid to volume folder
	sudo chown "$USER_ID":"$USER_ID" "$VOLUME_PATH"
	sudo chmod -R 777 "$VOLUME_PATH"
	sudo chmod -R g+s "$VOLUME_PATH"

}

#######################################
# Install GS applciation
# Globals:
#   DOCKER_CONTAINER_NAME, MULTICAST,
#   PUBLIC, MEMORY, SERVER_PORT,
#   SERVER_SSL_PORT, SERVER_POLICY_PORT,
#   DOCKER_CONTAINER_NAME, DOCKER_IMAGE_NAME,
#   DOCKER_IMAGE_VERSION, DOCKER_NETWORK,
#   DOCKER_VOLUME
# Arguments:
#   None
# Returns:
#   None
#######################################
install_server () {

	echo "Installing server...$DOCKER_CONTAINER_NAME"

	local SERVER_ID=0;

	SERVER_ID=$(get_container_id "$DOCKER_CONTAINER_NAME");

	if [[ -n "${SERVER_ID}" ]]; then
		sudo docker start "${SERVER_ID}";
		echo "Green Screens Service ($DOCKER_CONTAINER_NAME) is already installed."
		return 0;
	fi

	local IPLOC="";
	local IPPUB="";

	if [[ $MULTICAST == "false" ]]; then
		echo "Set cluster ip to local network";
		IPLOC=$(get_local_interface);
		IPPUB=$IPLOC;
		if [[ $PUBLIC == "true" ]]; then
			echo "Set cluster IP to public network";
			IPPUB=$(get_public_interface);
		fi
	fi

	sudo docker create -e GREENSCREENS_MULTICAST="$MULTICAST" \
		-v "${DOCKER_VOLUME}:/home/jboss/io.greenscreens" --net "$DOCKER_NETWORK" \
		-e JVM_MEM="$MEMORY" -m "${MEMORY}m" \
		-e LOC_ADDR="$IPLOC" -e PUB_ADDR="$IPPUB" \
		-p "$SERVER_PORT":8080 -p "$SERVER_SSL_PORT":8443 -p "$SERVER_POLICY_PORT":8843 \
		--name "$DOCKER_CONTAINER_NAME" "$DOCKER_IMAGE_NAME":"$DOCKER_IMAGE_VERSION"

	sudo docker network connect "$DOCKER_NETWORK" "$DOCKER_CONTAINER_NAME"

	SERVER_ID=$(get_container_id "$DOCKER_CONTAINER_NAME");

	if [[ -z "${SERVER_ID}" ]]; then
		echo "Green Screens Service ($DOCKER_CONTAINER_NAME) not installed."
	else
		echo "Starting Green Screens Service: $DOCKER_CONTAINER_NAME"
		sudo docker start "${SERVER_ID}";
		update_permissions
	fi
}

#######################################
# Print detected local interfaces
# Globals:
#   SERVER_PORT
# Arguments:
#   None
# Returns:
#   None
#######################################
print_local_interface () {

	local arr;
	read -r -a arr <<< "$(hostname -I)"

	echo "Local service at:"

	for i in "${arr[@]}"
	do
		echo "   http://${i}:${SERVER_PORT}"
	done
}

#######################################
# Print post install/update info
# Globals:
#   SERVER_PORT
# Arguments:
#   None
# Returns:
#   None
#######################################
print_info () {

	local IPPUBLIC=0;

	IPPUBLIC=$(get_public_interface);

	sudo docker inspect greenscreens | tee -a log.txt > /dev/null

	echo ""
	echo "!!! Check log.txt for instance details !!!"
	echo ""

	# echo "Local service at: http://${IPLOCAL}:${SERVER_PORT}"
	print_local_interface

	echo ""
	echo "Public service at: http://${IPPUBLIC}:${SERVER_PORT}"
	echo ""
	echo "WARNING: Public interface port might be different! Try standard ports 80 or 443."

	echo ""
	echo "Thank you for installing Green Screens Terminal Service."
	echo "In case you have any questions contact us via http://www.greenscreens.io/contact.html"
	echo ""
}

#######################################
# Check requirements for product install
# Check for Sudo, required tools and Docker
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
check_prerequisites () {

	root_checking
	install_sudo;
	install_hostname;
	get_os_info
	get_token
	check_os_info
	check_kernel
	check_hardware
	check_docker
	docker_sudoer

	echo "Prerequisites are OK."
}

#######################################
# Product install procedures,
# install Docker files and prepare instances
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
start_installation () {

	docker_login
	create_network
	create_volume
	download_dockerfile
	install_image
	update_server
	install_server
	install_system_service
	setup_nginx
	print_info

}

#######################################
# Main execution point
#######################################
check_prerequisites
start_installation

exit 0;
