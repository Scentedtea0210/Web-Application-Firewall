conda activate waf
CONDAPATH=$(which activate)
TITLE="source " 
TAIL=" waf;sudo python Dashboard.py;exec bash"
COMMAND=${TITLE}${CONDAPATH}${TAIL}

if [ $? -eq 0 ];
then
    echo 'The virtual enviroment has been created...'
else
    echo 'There is not an enviroment named waf...'
    conda create -n waf python=3.7
    pip install -r requirements.txt  -i https://pypi.mirrors.ustc.edu.cn/simple/
fi

GUI=$(cat Configuration.json | jq '.GUI')

if [[ $GUI =~ "True" ]];
then
    gnome-terminal --title='Dashboard' -x bash -c "$COMMAND"
fi


sudo python Firewall.py --json
