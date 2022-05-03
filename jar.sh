#!/bin/bash

mkdir temp
cp -a 

cp -a target/classes/* temp
cp -a extra imgs pom.xml  LICENSE  temp/
cd temp/
jar -cvf ../guardiankey.jar *
cd ..
rm -rf temp/

