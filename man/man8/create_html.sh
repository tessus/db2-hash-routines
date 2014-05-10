#!/bin/bash

for a in *.8
do
	i=${a%.*}
	man ./${i}.8 |man2html -topm 0 -botm 0 > ${i}.tmp1
	cat ${i}.tmp1 | awk "(NR==2) {print \"<HEAD><TITLE>${i}</TITLE></HEAD>\" } 1" > ${i}.tmp
	rm ${i}.tmp1
	LN=`grep -nm1 ADDRESS ${i}.tmp |cut -d: -f1`
	let START=${LN}-1
	let END=${START}+4
	sed "${START},${END}d" ${i}.tmp >$i.html
	rm ${i}.tmp
done
