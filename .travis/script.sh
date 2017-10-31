#!/usr/bin/env bash

set -ex

go get -t ./...
if [ ${TESTMODE} == "lint" ]; then 
  go get github.com/alecthomas/gometalinter
  gometalinter --install
  gometalinter --deadline=300s --tests ./...
fi

if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r -v -cover -randomizeAllSpecs -randomizeSuites -trace -skipPackage integrationtests,benchmark
fi

if [ ${TESTMODE} == "integration" ]; then
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -trace integrationtests
fi
