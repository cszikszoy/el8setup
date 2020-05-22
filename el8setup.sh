#!/bin/bash

####
# VARIABLES
####

# format: <server>:<port>
PROXY=""

# format: <server>:<nfs export path>
NFS_HOME=""

# $PROGRAM variable sets the name of various configuration files written by this script
PROGRAM=""

# output colors? if set to anything other than 'YES' colors will not be used
USE_COLORS=YES



####
# DO NOT CHANGE BELOW HERE
####

# EPEL repo
EPEL_REPO="http://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm"

# Zabbix repo
ZABBIX_REPO="https://repo.zabbix.com/zabbix/5.0/rhel/8/x86_64/zabbix-release-5.0-1.el8.noarch.rpm"

# terminal color codes
BLACK='\033[0;30m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

# disable colors if ${USE_COLORS} is anything other than "YES"
if [ "${USE_COLORS}" != "YES" ]; then
    BLACK=""
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    PURPLE=""
    CYAN=""
    WHITE=""
    RESET=""
fi

# various variables
PROGRAM_DEF="test"



####
# Check if we're root fist
####
if [[ ${EUID} -ne 0 ]]; then
    echo -e "${RED}This script must be run as root!${RESET}"
    exit 1
fi



####
# FUNCTIONS
####
confirm() {
    # call with a prompt string or use a default
    echo -n -e "${BLUE}${1:-Are you sure?} [${GREEN}Y${BLUE}/${RED}n${BLUE}] ${YELLOW}"
    read RESPONSE
    echo -n -e ${RESET}
    case "${RESPONSE}" in
        [nN][oO]|[nN])
            false
            ;;
        *)
            true
            ;;
    esac
}

prompt() {
    read -r -p "$1" RESPONSE
    echo ${RESPONSE}
}

systemd_enable() {
    systemd_cmd "enable --now" ${1}
}

systemd_disable() {
    systemd_cmd "disable --now" ${1}
}

systemd_restart() {
    systemd_cmd restart ${1}
}

systemd_cmd() {
    systemctl status --no-pager ${2}
    systemctl ${1} ${2}
    systemctl status --no-pager ${2}
}



####
# BASIC SETUP - DON'T ASK
####
# did we get a valid ${PROGRAM} variable?
if [[ -z "${PROGRAM}" ]]; then
    PROGRAM="${PROGRAM_DEF}"
fi



####
# KDUMP
####
if confirm "Disable KDUMP?"; then
    systemd_disable kdump
fi




####
# LOGIN DEFS
####
if confirm "Set more permissive homedir?"; then
    # set the umask to 027 in ligon.defs (sets default homedir perms to 750)
    sed -i -e 's|^UMASK.*$|UMASK 027|' /etc/login.defs
fi



####
# SSL CERTS
####
if confirm "Install SSL certs?"; then
    CERTDIR="/etc/pki/ca-trust/source/anchors"
    cp *.cer ${CERTDIR} &> /dev/null
    cp *.crt ${CERTDIR} &> /dev/null
    update-ca-trust
fi



####
# PROXY
####
if confirm "Configure proxy?"; then
    DNFCONF="/etc/dnf.conf"

    # remove any old proxy or timeout lines
    sed -i -e '/^proxy=/d' ${DNFCONF} &> /dev/null
    sed -i -e '/^timeout=/d' ${DNFCONF} &> /dev/null

    # Add proxy and timeout to yum
    echo "proxy=http://${PROXY}" >> ${DNFCONF}
    echo "timeout=300" >> ${DNFCONF}

    PROXYSH="/etc/profile.d/proxy.sh"

    # export the http_proxy variable for all users
    echo "# export proxy for all users" > ${PROXYSH}
    echo "export http_proxy=http://${PROXY}" >> ${PROXYSH}
    echo "export https_proxy=http://${PROXY}" >> ${PROXYSH}

    # run proxy script to export the variables for the current session too
    . ${PROXYSH}
fi



####
# SELINUX
####
if confirm "Turn off SELinux?"; then
    # turn off selinux
    if [[ $(getenforce) == "Enforcing" ]]; then
        # turn off selinux for now
        setenforce 0
    fi

    # make sure it doesn't come back
    sed -i -e 's|^SELINUX=.*|SELINUX=disabled|' /etc/selinux/config
fi



####
# FIREWALL
####
if confirm "Disable firewall?"; then
    # disable firewall
    systemd_disable firewalld
else
    # disable unnecessary services
    firewall-cmd --permanent --remove-service=dhcpv6-client
    firewall-cmd --permanent --remove-service=cockpit
    firewall-cmd --reload
fi



####
# BASE PACKAGE INSTALL
####
if confirm "Install & configure base packages?"; then
  # add EPEL repo
    if grep CentOS /etc/redhat-release; then
        # epel-release is already in the centos repos
        dnf install -y epel-release
    else
        # we need to do some more work on redhat
        dnf install -y ${EPEL_REPO}
    fi

    # install deltarpm
    dnf install -y drpm

    # update
    dnf update -y

    # install basic packages
    dnf install -y dkms nano net-tools htop rsync bind-utils htop byobu

    # install global nanorc
    cp ./nanorc /etc/nanorc

    ####
    # EXTRA PACKAGE INSTALL
    ####
    if confirm "Install & configure extra packages?"; then
        # install extra pacakges
        dnf --enablerepo=PowerTools install -y ntfs-3g system-storage-manager snapd fuse-sshfs

        # enable snapd
        systemd_enable snapd.socket

        # create snapd symlink
        ln -s /var/lib/snapd/snap /snap

        # maybe set snapd http proxy
        if [[ ! -z "${http_proxy}" ]]; then
            snap set system proxy.http="${http_proxy}"
        fi

        # maybe set snapd https proxy
        if [[ ! -z "${https_proxy}" ]]; then
            snap set system proxy.https="${https_proxy}"
        fi
    fi
fi



####
# DNF-AUTOMATIC
####
if confirm "Setup dnf-automatic?"; then

    DNFAUTOCONF="/etc/dnf/automatic.conf"

    # install dnf-automatic
    dnf install -y dnf-automatic

    # update dnf-automatic config file
    sed -i -e 's|^download_updates =.*|download_updates = yes|' ${DNFAUTOCONF}
    sed -i -e 's|^apply_updates =.*|apply_updates = yes|' ${DNFAUTOCONF}
    sed -i -e 's|^random_sleep =.*|random_sleep = 5|' ${DNFAUTOCONF}

    # enable & start dnf-automatic?
    systemd_enable dnf-automatic.timer
fi



####
# SQUID
####
if confirm "Install Squid proxy?"; then
    # install squid
    dnf -y install squid

    # squid config file
    SQUID_CONF_FILE="/etc/squid/squid.conf"

    # backup original squid config file
    mv ${SQUID_CONF_FILE} ${SQUID_CONF_FILE}.bak

    # start config file by writing ACLs
    while : ; do
        # ask for ACL
        ACL=$(prompt "Enter ACL in CIDR (<IP>/<mask>) form: ")

        # if we didn't get a group, break the loop
        [[ -z ${ACL:+x} ]] && break

        # add this group to sudoers
        echo "acl localnet src ${ACL}" > ${SQUID_CONF_FILE}
    done

    # configure squid
    read -r -d '' SQUID_CONF <<EOF

# allow only http & https
acl SSL_ports port 443
acl Safe_ports port 80      # http
acl Safe_ports port 443     # https
acl CONNECT method CONNECT

# Deny requests to certain unsafe ports
http_access deny !Safe_ports

# Deny CONNECT to other than secure SSL ports
http_access deny CONNECT !SSL_ports

# Only allow cachemgr access from localhost
http_access allow localhost manager
http_access deny manager

# We strongly recommend the following be uncommented to protect innocent
# web applications running on the proxy server who think the only
# one who can access services on "localhost" is a local user
http_access deny to_localhost

# Example rule allowing access from your local networks.
# Adapt localnet in the ACL section to list your (internal) IP networks
# from where browsing should be allowed
http_access allow localnet
http_access allow localhost

# And finally deny all other access to this proxy
http_access deny all

# Squid normally listens to port 3128
http_port 3128

# Uncomment and adjust the following to add a disk cache directory.
cache_dir ufs /var/spool/squid 100 16 256

# Leave coredumps in the first cache dir
coredump_dir /var/spool/squid

# refresh patterns
refresh_pattern -i (/cgi-bin/|\?) 0 0%  0
refresh_pattern .       0   20% 4320

# hide ip address of requestor
forwarded_for off

# deny these types of header requests
request_header_access From deny all
request_header_access Server deny all
request_header_access Referer deny all
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all

EOF

    # write rest of squid config file
    echo "${SQUID_CONF}" >> ${SQUID_CONF_FILE}

    # enable & start squid
    systemd_enable squid

    # is the firewall on?
    if [[ $(firewall-cmd --state) -eq 0 ]]; then
        # allow squid port
        firewall-cmd --permanent --add-service=squid
        firewall-cmd --reload
    fi
fi



####
# SUDOERS
####
if confirm "Setup sudoers?"; then
    # create sudoers file
    read -r -d '' SUDOERS_CONF <<'EOF'
# keep $EDITOR
Defaults env_keep += "EDITOR"
EOF

    # write sudoers file
    echo "${SUDOERS_CONF}" >> /etc/sudoers.d/${PROGRAM}
fi



####
# ZABBIX AGENT
####
if confirm "Install Zabbix agent?"; then
    # add zabbix repo
    dnf install -y ${ZABBIX_REPO}
    dnf install -y zabbix-agent2

    # prompt for zabbix server
    echo -n -e "${CYAN}Enter Zabbix server or proxy (IP or FQDN): ${YELLOW}"
    read ZABBIX_AGENT_SERVER
    echo -e "${RESET}"

    # comment out DenyKey in agent base config to enable remote commands
    sed -i -e 's|^DenyKey=|#DenyKey|' /etc/zabbix/zabbix_agent2.conf


    # configure zabbix-agent
    read -r -d '' ZABBIX_AGENT_CONF <<EOF
Server=${ZABBIX_AGENT_SERVER}
ServerActive=${ZABBIX_AGENT_SERVER}
Hostname=$(hostname -f)
Plugins.SytstemRun.LogRemoteCommands=1
EOF

    # save zabbix config file path to variable
    ZABBIX_AGENT_CONF_FILE="/etc/zabbix/zabbix_agent2.d/${PROGRAM}.conf"

    # write zabbix config file
    echo "${ZABBIX_AGENT_CONF}" > ${ZABBIX_AGENT_CONF_FILE}

    # write zabbix sudoers file
    echo "# Allow the zabbix user to sudo without a password" > /etc/sudoers.d/zabbix
    echo "zabbix  ALL=NOPASSWD:   ALL" >> /etc/sudoers.d/zabbix

    # monitored by proxy too?
    if confirm "Monitored by additional server or proxy?"; then
        # prompt for zabbix proxy
        echo -n -e "${CYAN}Enter second Zabbix server or proxy (IP or FQDN): ${YELLOW}"
        read ZABBIX_AGENT_PROXY
        echo -e "${RESET}"

        # add zabbix proxy to server & active
        sed -i "/^Server=/ s|$|,${ZABBIX_AGENT_PROXY}|" ${ZABBIX_AGENT_CONF_FILE}
        sed -i "/^ServerActive=/ s|$|,${ZABBIX_AGENT_PROXY}|" ${ZABBIX_AGENT_CONF_FILE}
    fi

    # set ownership to root:zabbix
    chown -R root:zabbix /etc/zabbix

    # enable & start zabbix-agent
    systemd_enable zabbix-agent2

    # is the firewall on?
    if [[ $(firewall-cmd --state) -eq 0 ]]; then
        # allow zabbix passive agent port
        firewall-cmd --permanent --add-service=zabbix-agent
        firewall-cmd --reload
    fi
fi



####
# ZABBIX PROXY
####
if confirm "Install Zabbix proxy?"; then
    # add zabbix repo
    dnf install -y ${ZABBIX_REPO}

    # install mariadb
    dnf install -y mariadb-server mariadb

    # enable & start mariadb
    systemd_enable mariadb

    # prompt for db root password
    echo -n -e "${CYAN}Enter mysql root password: ${YELLOW}"
    read MYSQL_PWD
    echo -e "${RESET}"

    # do everything that mysql_secure_setup would do
    mysql -uroot <<EOF
UPDATE mysql.user SET Password=PASSWORD('${MYSQL_PWD}') WHERE User='root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test_%';
FLUSH PRIVILEGES;
EOF

    # install zabbix proxy w/ mysql
    dnf install -y zabbix-proxy-mysql zabbix-get nmap traceroute

    # prompt for db zabbix password
    echo -n -e "${CYAN}Enter mysql zabbix password: ${YELLOW}"
    read ZABBIX_PROXY_DB_PWD
    echo -e "${RESET}"

    mysql -u root -p${MYSQL_PWD} <<EOF
create database zabbix character set utf8 collate utf8_bin;
create user 'zabbix'@'localhost' identified by '${ZABBIX_PROXY_DB_PWD}';
grant all privileges on zabbix.* to 'zabbix'@'localhost';
EOF

    # import initial schema
    zcat /usr/share/doc/zabbix-proxy-mysql*/schema.sql.gz | mysql -uzabbix -p${ZABBIX_PROXY_DB_PWD} zabbix

    # prompt for server
    echo -n -e "${CYAN}Enter Zabbix server (IP or FQDN): ${YELLOW}"
    read ZABBIX_PROXY_SERVER
    echo -e "${RESET}"

    # prompt for proxy name
    echo -n -e "${CYAN}Enter host name of this proxy (must match in Zabbix server) or blank to use system hostname ($(hostname -f)): ${YELLOW}"
    read ZABBIX_PROXY_HOSTNAME
    echo -e "${RESET}"

    # was anything entered for the proxy name? if not, use the full system hostname
    [[ -z ${ZABBIX_PROXY_HOSTNAME:+x} ]] && ZABBIX_PROXY_HOSTNAME=$(hostname -f)

    # configure zabbix-proxy
    read -r -d '' ZABBIX_PROXY_CONF <<EOF
Server=${ZABBIX_PROXY_SERVER}
Hostname=${ZABBIX_PROXY_HOSTNAME}
EnableRemoteCommands=1
LogRemoteCommands=1
DBName=zabbix
DBPassword=${ZABBIX_PROXY_DB_PWD}
ProxyOfflineBuffer=72
ConfigFrequency=60
EOF

    # maybe make zabbix proxy conf dir (sometimes it doesn't exist...)
    mkdir -p /etc/zabbix/zabbix_proxy.d

    # write our zabbix config file
    echo "${ZABBIX_PROXY_CONF}" > /etc/zabbix/zabbix_proxy.d/${PROGRAM}.conf

    # tell main zabbix proxy config to read conf files in subdir
    sed -i -e "/^# Include=$/a\\\nInclude=/etc/zabbix/zabbix_proxy.d/*.conf" /etc/zabbix/zabbix_proxy.conf

    # set ownership to root:zabbix
    chown -R root:zabbix /etc/zabbix

    # enable & start zabbix proxy
    systemd_enable zabbix-proxy

    # is the firewall on?
    if [[ $(firewall-cmd --state) -eq 0 ]]; then
        # allow zabbix active agent port
        firewall-cmd --permanent --add-service=zabbix-server
        firewall-cmd --reload
    fi
fi



####
# COLORS TO PS1
####
if confirm "Add colors to PS1?"; then
    # add colors to PS1
    read -r -d '' PS <<'EOF'
# color PS1
PS1='\[\033[01;32m\]\u\[\033[00m\]@\[\033[01;31m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
EOF

    # write colors to users
    echo "$PS" > /etc/profile.d/colors.sh

    # write colors to root
    echo "" >> /root/.bashrc
    echo "$PS" >> /root/.bashrc
fi



####
# SSSD / DOMAIN JOIN
####
if confirm "Join domain?"; then
    # install packages and discover domain
    dnf install -y sssd realmd

    # prompt for domain
    echo -n -e "${CYAN}Enter domain to join: ${YELLOW}"
    read DOMAIN
    echo -e "${RESET}"

    # try to discover domain
    REALM_DISCOVER=$(realm discover ${DOMAIN})

    # quit if we can't discover it
    if [ $? -ne 0 ]; then
        echo "Domain discovery for ${DOMAIN} failed!"
        exit 1
    fi

    # get realm type
    REALM_TYPE=$(echo "${REALM_DISCOVER}" | grep "type:" | awk -F ' ' '{print $2}' | tr -d '\n')

    # only jon kerberos (AD) domains
    if [[ "${REALM_TYPE}" != "kerberos" ]]; then
        echo "Can't join non 'kerberos' domains!"
        exit 1
    fi

    # get list of packages required for the realm
    REALM_PACKAGES=$(echo "${REALM_DISCOVER}" | grep "required-package:" | awk -F ' ' '{print $2}' | tr '\n' ' ')
    # and install them
    dnf -y install ${REALM_PACKAGES}

    # prompt for realm join unsername
    echo -n -e "${CYAN}Enter username to perform domain join: ${YELLOW}"
    read USER
    echo -e "${RESET}"

    # join domain
    realm join -U ${USER} ${DOMAIN} || exit 1

    # ask which group to permit
    if confirm "Restrict access to group? (No means allow all domain users)"; then
        while : ; do
            # ask for group
            GROUP=$(prompt "Enter AD group to allow (blank to stop adding groups): ")
            # if we didn't get a group, break the loop
            [[ -z ${GROUP:+x} ]] && break
            # add this group to the permit list
            realm permit -g "${GROUP}"
        done
    else
        # permit all
        realm permit --all
    fi

    # fix sssd conf
    sed -i -e 's|.*fully_qualified_names.*|use_fully_qualified_names = False|' /etc/sssd/sssd.conf
    sed -i -e '/services = nss, pam/a override_space = _' /etc/sssd/sssd.conf
    sed -i -e 's|.*homedir.*|override_homedir = /home/%u|' /etc/sssd/sssd.conf

    # don't enable gpo based access control (https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/sssd-gpo)
    # if a group policy object in a domain is broken all logins will be prevented, so just disable it (https://bugzilla.redhat.com/show_bug.cgi?id=1364559)
    echo "ad_gpo_access_control = disabled" >> /etc/sssd/sssd.conf

    # don't do dynamic dns updates (https://access.redhat.com/solutions/4437901)
    echo "dyndns_update = False" >> /etc/sssd/sssd.conf

    # add domain_admins to sudoers?
    if confirm "Add domain_admins to sudoers?"; then
        # add domain admins from AD to sudoers file
        echo "" >> /etc/sudoers.d/${PROGRAM}
        echo "# domain_admins have sudo access" >> /etc/sudoers.d/${PROGRAM}
        echo "%domain_admins    ALL=(ALL)   ALL" >> /etc/sudoers.d/${PROGRAM}
    fi

    # maybe add other groups to sudoers
    if confirm "Add other groups to sudoers?"; then
        while : ; do
            # ask for group
            GROUP=$(prompt "Enter AD group to add (blank to stop adding groups): ")
            # if we didn't get a group, break the loop
            [[ -z ${GROUP:+x} ]] && break
            # add this group to sudoers
            echo "# ${GROUP} have sudo access" >> /etc/sudoers.d/${PROGRAM}
            echo "%${GROUP}    ALL=(ALL)   ALL" >> /etc/sudoers.d/${PROGRAM}
        done
    fi

    # restart sssd
    systemd_restart sssd

    # remove gnome-initial-setup if we joined a domain
    dnf remove -y gnome-initial-setup
fi


######### FIXME FOR EL8
####
# NFS
####
if confirm "Install NFS?"; then
    # install nfs
    dnf install -y nfs-utils autofs

    # create autofs files
    echo -e "/mnt/nfs\t/etc/auto.${PROGRAM}" > /etc/auto.master.d/${PROGRAM}.autofs
    touch /etc/auto.${PROGRAM}

    if confirm "NFS \$HOME?"; then
        # add homedir nfs mount
        echo -e "home\t${NFS_HOME}" >> /etc/auto.${PROGRAM}

        # set homedirs to NFS in sssd
        sed -i -e 's|.*homedir.*|override_homedir = /mnt/nfs/home/%u|' /etc/sssd/sssd.conf

        # restart sssd to pick up homedir changes
        systemd_restart sssd
    fi

    # set autofs timeout to 0
    sed -i -e 's|[#]\+OPTIONS=.*$|OPTIONS="--timeout=0"|' /etc/sysconfig/autofs

    # enable & start nfs services
    systemd_enable nfs
    systemd_enable nfs-lock
    systemd_enable rpcbind
    systemd_enable autofs
fi


######### FIXME FOR EL8
####
# XRDP
####
if confirm "Install XRDP?"; then
    # install packages
    yum install -y tigervnc-server xrdp

    #enable xrdp service
    systemd_enable xrdp

    # is the firewall on?
    if [[ $(firewall-cmd --state) -eq 0 ]]; then
        # allow RDP port
        firewall-cmd --permanent --add-service=ms-wbt
        firewall-cmd --reload
    fi
fi



####
# CLEANUP
####
# autoremove things we don't need
dnf autoremove -y



####
# VIRTUAL?
####
VIRTUAL=$(systemd-detect-virt)
if [ $? -eq 0 ]; then
    # if we're virtual need to allow chrony to step the clock at any time
    sed -i -e 's|^makestep.*|makestep 3 -1|' /etc/chrony.conf

    # restart chronyd
    systemd_restart chronyd

    # install VMware tools?
    if confirm "Install VM-Tools?"; then
        # install open-vm-tools if we're virtualized
        if [[ ${VIRTUAL} == "vmware" ]]; then
            dnf install -y open-vm-tools

            # enable & start vmtoolsd
            systemd_enable vmtoolsd

            # reboot... sometimes starting vmtoolsd kills our network connection
            reboot -n
        else
            echo -e "${RED}Not VMware... skipping.${RESET}"
        fi
    fi
fi


####
# END
####
echo -n -e "${RED}Don't forget to logout or restart before using this system!${RESET}"
echo
