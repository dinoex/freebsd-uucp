#!/bin/sh
make distclean
up=`( cd .. && pwd )`
down=`pwd`
name=${down##${up}/}
(cd .. && tar -cvf tar ${name})
mv ../tar ${name}.tar
bzip2 ${name}.tar
