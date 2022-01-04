#$1 is the prefix of final log
services=$(systemctl list-unit-files |grep -v UNIT|grep -v listed|awk -F' ' '{print $1}')
analyze_log=$1
if [ -z $1 ]; then
    echo "please specify logfile"
    exit 0
fi
if [ -e $analyze_log ]; then
    echo "$analyze_log exists, exit!"
    exit 0
fi
echo "analyze log:$analyze_log"
for service in $services; do 
    echo "checking $service" >> $analyze_log
    systemd-analyze verify $service >> $analyze_log 2>&1
done