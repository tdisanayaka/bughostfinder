apt update
apt upgrade -y
apt install python python-pip -y
pip install -r requirements.txt
mv bugfinder.py /data/data/com.termux/files/usr/bin/bughfinder
chmod +x /usr/bin/bughfinder
