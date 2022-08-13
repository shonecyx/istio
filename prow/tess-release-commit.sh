#!/bin/bash

# XXX: prow job use this script to test and build now. Upstream prow
# jobs use script in `prow` folder or `make` command directly, and
# istio.io/release-builder is used to build docker images.
build_option=$1
EXIT_CODE=0

########################################################
#
# Command help
#
########################################################
function command_help() {
    echo "bash tess-release-commit.sh <option>"
    echo "options: release"
    echo "         unit-test"
    echo "         lint-go"
    echo
    EXIT_CODE=127
}

########################################################
#
# Release
#
########################################################
function release() {
  # Commmon settings
  prerequisites

  make push
  EXIT_CODE=$?
}

########################################################
#
# Unit Test
#
########################################################
function unit_test() {
  # Commmon settings
  prerequisites

  # Additional env vars
  export ISTIO_SRC_DIR="`pwd`"
  export PILOT_CERT_DIR="`pwd`/tests/testdata/certs/pilot"
  export ISTIO_BOOTSTRP_TEMPLATE_DIR="`pwd`"

  # Pull envoy binary, which is needed by pilot-test
  make depend
  # Fire the test
  # disabled tests: mixer galley security
  go test -race -v ./pilot/... ./istioctl/... ./pkg/kube/...
  EXIT_CODE=$?
}

########################################################
#
# Lint-go
#
########################################################
function lint_go() {
  # Commmon settings
  prerequisites

  # Additional settings
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.22.2
  export PATH="$PATH:$GOPATH/bin:./bin/"

  make lint-go
  EXIT_CODE=$?
}

########################################################
#
# pre-requesities
#
########################################################
function prerequisites() {
  echo "Preparing the environments..."

  # GOPATH should be exported externally
  export HUB='hub.tess.io/istio-testing'
  export GOPROXY='https://proxy.golang.org'
  export BUILD_WITH_CONTAINER='0'
  export VERBOSE='1'
  export ISTIO_RELEASE=1.10.4
  export TAG="$ISTIO_RELEASE-`git rev-parse --short HEAD`"
  export PATH="$PATH:$GOPATH/bin"
  export GOPRIVATE='tess.io'

  git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.corp.ebay.com".insteadOf "git+ssh://git@github.corp.ebay.com"

  if [[ -n ${PROW_JOB_ID:-} ]]; then
    # need login to pull/push docker images
    mkdir ~/.docker
    export DOCKER_CONFIG=~/.docker

    echo "login hub.tess.io as user $DOCKERHUB_ROBOT_NAME"
    if [[ -n ${DOCKERHUB_ROBOT_TOKEN:-} ]]; then
      echo "${DOCKERHUB_ROBOT_TOKEN}" | \
        docker login -u="${DOCKERHUB_ROBOT_NAME}" --password-stdin hub.tess.io
    fi

    if [[ ${JOB_TYPE} == "presubmit" ]]; then
      # set tag to PR's last commit SHA
      export TAG="$ISTIO_RELEASE-${PULL_PULL_SHA::10}"
    else
      export TAG="$ISTIO_RELEASE-${PULL_BASE_SHA::10}"
    fi

    echo "docker image tag: $TAG"

    # REPO_ROOT is required by test case for locating test data
    export REPO_ROOT=/workspace/istio
  fi
}

########################################################
#
# Main program starts from here
#
########################################################

if [[ $build_option == "release" ]]; then
  release
elif [[ $build_option == "unit-test" ]]; then
  unit_test
elif [[ $build_option == "lint" ]]; then
  lint_go
else
  echo "Bad command, please refer to below usage"
  echo
  command_help
fi

exit $EXIT_CODE
