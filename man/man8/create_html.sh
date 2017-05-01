#!/bin/bash

MAN2HTML=man2html
M2H=`$MAN2HTML -help |head -1 |awk '{print $1}'`

if [ `uname` != "Linux" ]; then
	echo "+--------------------------------------------+"
	echo "| Warning: this script will most likely      |"
	echo "|          only run on Linux                 |"
	echo "+--------------------------------------------+"
	echo -ne "Proceed anyway (y/n): "
	read x
	if [ x$x != "xy" ]; then
		exit
	fi
	echo
fi

if [ "$M2H" != "Usage:" ]; then
	echo "+--------------------------------------------+"
	echo "| Error: man2html 3.0.1 (CPAN) needed        |"
	echo "|        please install it                   |"
	echo "+--------------------------------------------+"
	echo -ne "Try to install it temporarily (y/n): "
	read x
	if [ x$x != "xy" ]; then
		exit
	fi
	curl -sS http://search.cpan.org/CPAN/authors/id/E/EH/EHOOD/man2html3.0.1.tar.gz -o /tmp/man2html.tar.gz
	tar -C /tmp -xzf /tmp/man2html.tar.gz
	MAN2HTML="perl /tmp/man2html3.0.1/$MAN2HTML"
	echo
fi

mkdir -p html

for a in *.8
do
	i=${a%.*}
	man ./${i}.8 |$MAN2HTML -topm 0 -botm 0 > ${i}.tmp1
	cat ${i}.tmp1 | awk "(NR==2) {print \"<HEAD><TITLE>${i}</TITLE></HEAD>\" } 1" > ${i}.tmp
	rm ${i}.tmp1
	LN=`grep -nm1 ADDRESS ${i}.tmp |cut -d: -f1`
	let START=${LN}-1
	let END=${START}+4
	sed "${START},${END}d" ${i}.tmp >html/$i.html
	rm ${i}.tmp
done

echo "----------------------------------------------------------------------"
echo "HTML files created in: `pwd`/html"
echo "----------------------------------------------------------------------"
