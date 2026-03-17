#!/bin/bash

SCRIPT_DIR=$(dirname $0)
TF_DIR=${SCRIPT_DIR}/tf
REPO_DIR=${SCRIPT_DIR}/..
TARGET_DIR=${REPO_DIR}/target

SSH_USER="ec2-user"
KEY_PATH=""
REBUILD="false"
ECHO=""

EXAMPLES="http-server tcp-echo-server tcp-echo-client hyper udp-server udp-client"

function usage() {
    echo "Usage: $0 [-h] -k <key_path> [-u <user>]"
    echo "  -h, --help       Show this help message and exit"
    echo "  -k, --key-path   Path to the SSH key. Required."
    echo "  -u, --user       User to sync with. Default: ${SSH_USER}"
    echo "  -r, --rebuild    Rebuild the examples. Default: ${REBUILD}"
    echo "  -d, --dry-run    Dry run the script."
}

function build_examples() {
    pushd ${REPO_DIR} > /dev/null
    ${ECHO} cargo build --profile profiling --examples
    popd > /dev/null
}

function sync_examples() {
    local KEY_PATH=$1
    local USER=$2
    local IP=$3

    local BINS=""
    for ex in ${EXAMPLES}; do
        BINS="${BINS} ${TARGET_DIR}/profiling/examples/${ex}"
    done

    ${ECHO} scp -i ${KEY_PATH} ${BINS} ${USER}@${IP}:~/
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

function main() {
    local KEY_PATH=$1
    local USER=$2
    local REBUILD=$3

    if [ "${REBUILD}" == "true" ]; then
        build_examples
    fi

    for IP in $(get_ips); do
        echo "Syncing to ${USER}@${IP}"
        sync_examples ${KEY_PATH} ${USER} ${IP}
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
