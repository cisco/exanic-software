#!/bin/bash

help=0

# Borrowed from the following post: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
POSITIONAL=()
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        -h|--help)
        help=1
        shift # past argument
        shift # past value
        ;;
        -o|--output-filepath)
        output_filepath="$2"
        shift # past argument
        shift # past value
        ;;
        --default)
        default=YES
        shift # past argument
        ;;
        *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

product="exanic"
product_pretty="ExaNIC"
timestamp="$(date +%F-%HH%MM%S.%N)"
filename="${HOSTNAME}_${product}_debug_dump_${timestamp}.log"
filepath="${HOME}/${filename}"

if [ ${help} -eq 1 ]
then
    echo "This script captures debug information relevant to troubleshooting a Cisco ${product_pretty} installation."
    echo "By default, this debug dump will be located at the following location:"
    echo ""
    echo ${filepath}
    echo ""
    echo "This location can be overridden by the '-o' argument."
    echo "If possible, please run this script as a superuser via 'sudo'."
    echo "Note that if this script is run as a superuser, the debug dump's default location will change to the following:"
    echo ""
    echo "/root/${filename}"
    echo ""
    echo "Usage:"
    echo "    -o: Define the filepath (absolute or relative) and filename where the debug dump will be placed."
    echo "    -h: Display this help message."
    exit 1
fi

# If output filepath is defined, override filepath variable with new location
if [ -n "${output_filepath}" ]
then
    filepath="${output_filepath}"
fi

cmds=(
    "date"
    "lspci -vv"
    "which exanic-config"
    "exanic-config -v"
    "ls /dev/exanic*"
    "cat /proc/cmdline"
    "cat /etc/os-release"
    "uname -a"
    "ipmiutil sensor"
    "ipmiutil sel"
    "ipmiutil health"
    "yum list installed"
    "apt list --installed"
    "dkms status"
    "chkconfig --list ntpd"
    "ntpq -p"
    "ntpstat"
    "ls /etc/udev/rules.d/"
    "date"
)

echo "Writing Debug Dump to ${filepath}..."

echo "---------- Cisco ${product_pretty} Debug Dump ----------" &>> $filepath
for cmd in "${cmds[@]}"; do
    echo \`$cmd\` &>> $filepath
    $cmd &>> $filepath
    echo "" &>> $filepath # Newline
done

echo "Debug Dump has completed!"