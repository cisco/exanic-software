#!/bin/bash

help=0
compress_file=1

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
        -c|--disable-compression)
        compress_file=0
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
final_filename="${filename}.gz"
final_filepath="${filepath}.gz"

if [ ${help} -eq 1 ]
then
    echo "This script captures debug information relevant to troubleshooting a"
    echo "Cisco ${product_pretty} installation."
    echo ""
    echo "By default, this debug dump will be located at the following location:"
    echo ""
    echo ${final_filepath}
    echo ""
    echo "This location can be overridden by the '-o' argument."
    echo ""
    echo "This script will prompt for superuser credentials, as some commands"
    echo "must be run with sudo."
    echo ""
    echo "Usage:"
    echo "    -o: Define the filepath (absolute or relative) and filename where"
    echo "        the debug dump will be placed. Note that this file will be"
    echo "        gunzipped, so '.gz' will be appended to the end of it."
    echo "    -h: Display this help message."
    exit 1
fi

# If output filepath is defined, override filepath variable with new location
if [ -n "${output_filepath}" ]
then
    filepath="${output_filepath}"
fi

sudo -v

cmds=(
    "date"
    "sudo lspci -vv"
    "which exanic-config"
    "sudo exanic-config -v"
    "ls /dev/exanic*"
    "dmesg"
    "cat /proc/cmdline"
    "cat /etc/os-release"
    "uname -a"
    "sudo ipmiutil sensor"
    "sudo ipmiutil sel"
    "sudo ipmiutil health"
    "yum list installed"
    "apt list --installed"
    "dkms status"
    "chkconfig --list ntpd"
    "ntpq -p"
    "ntpstat"
    "ls /etc/udev/rules.d/"
    "cat /etc/udev/rules.d/exanic*"
    "top -b -n 1"
    "date"
)

echo "Executing Debug Dump commands..."

echo "---------- Cisco ${product_pretty} Debug Dump ----------" &>> $filepath
for cmd in "${cmds[@]}"; do
    echo \`$cmd\` &>> $filepath
    $cmd &>> $filepath
    echo "" &>> $filepath # Newline
done

if [ ${compress_file} -eq 1 ]
then
    echo "Compressing Debug Dump..."
    gzip $filepath
fi

echo "Debug Dump has completed!"

if [ ${compress_file} -eq 1 ]
then
    echo "File location: ${final_filepath}" 
else
    echo "File location: ${filepath}"
fi
