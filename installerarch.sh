pacman -Syu
pacman -S python python-pip
pip install -r requirements.txt  --break-system-packages
mv bugfinders.py /usr/bin/bughfinder
chmod +x /usr/bin/bughfinder
