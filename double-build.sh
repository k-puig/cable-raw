#!/bin/bash

cd ./cable-client
./gradlew build
cd ../cable-server
./gradlew build

echo
echo
echo Done!
