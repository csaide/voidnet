#!/bin/bash

SCRIPT_DIR=$(dirname $0)
TF_DIR=${SCRIPT_DIR}/tf
REPO_DIR=${SCRIPT_DIR}/..
TARGET_DIR=${REPO_DIR}/target
XDP_TOOLS_DIR=${REPO_DIR}/vendor/xdp-tools

SSH_USER="ec2-user"
KEY_PATH=""
REBUILD="false"
ECHO=""

function usage() {
    echo "Usage: $0 [-h] -k <key_path> [-u <user>]"
    echo "  -h, --help       Show this help message and exit"
    echo "  -k, --key-path   Path to the SSH key. Required."
    echo "  -u, --user       User to sync with. Default: ${SSH_USER}"
    echo "  -r, --rebuild    Rebuild the examples and xdp-tools. Default: ${REBUILD}"
    echo "  -d, --dry-run    Dry run the script. Default: ${DRY_RUN}"
}

function build_examples() {
    pushd ${REPO_DIR}
    ${ECHO} cargo build --release --examples
    popd > /dev/null
}

function build_xdp_tools() {
    pushd ${XDP_TOOLS_DIR}
    ${ECHO} ./configure
    ${ECHO} make
    popd > /dev/null
}

function sync_examples() {
    local KEY_PATH=$1
    local USER=$2
    local IP=$3

    ${ECHO} scp -i ${KEY_PATH} ${TARGET_DIR}/release/examples/{rx-bench,tx-bench,echo,rx-mt,tx-mt} ${USER}@${IP}:~/
}

function sync_xdp_tools() {
    local KEY_PATH=$1
    local USER=$2
    local IP=$3

    ${ECHO} scp -i ${KEY_PATH} ${XDP_TOOLS_DIR}/{xdp-bench/xdp-bench,xdp-trafficgen/xdp-trafficgen} ${USER}@${IP}:~/
}

function get_ips() {
    pushd ${TF_DIR} > /dev/null
    local OUTPUT=$(terraform output -json)
    if [[ ${OUTPUT} == "{}" ]]; then
        echo "Error: No output from Terraform" >&2
        exit 1
    fi

    echo ${OUTPUT} | jq -r '.node_ips.value[]'
    popd > /dev/null
}

function sync_all() {
    local KEY_PATH=$1
    local USER=$2
    local IP=$3

    sync_examples ${KEY_PATH} ${USER} ${IP}
    sync_xdp_tools ${KEY_PATH} ${USER} ${IP}
}

function main() {
    local KEY_PATH=$1
    local USER=$2
    local REBUILD=$3

    if [ "${REBUILD}" == "true" ]; then
        build_examples
        build_xdp_tools
    fi

    for IP in $(get_ips); do
        echo "Syncing to ${USER}@${IP}"
        sync_all ${KEY_PATH} ${USER} ${IP}
    done
}

while [ "$#" -gt 0 ]; do
    case ${1} in
        "-h" | "--help")
            usage
            exit 1
            ;;
        "-k" | "--key-path")
            KEY_PATH=$2
            shift 2
            ;;
        "-u" | "--user")
            SSH_USER=$2
            shift 2
            ;;
        "-r" | "--rebuild")
            REBUILD="true"
            shift
            ;;
        "-d" | "--dry-run")
            ECHO="echo"
            shift
            ;;
    esac
done

if [ -z "${KEY_PATH}" ]; then
    echo "Error: Key path is required"
    usage
    exit 1
fi

if [ -z "${SSH_USER}" ]; then
    echo "Error: User is required"
    usage
    exit 1
fi

main ${KEY_PATH} ${SSH_USER} ${REBUILD}
