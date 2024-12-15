pacman -Syu
pacman -S python python-pip
pip install -r requirements.txt
mv bugfinder.py /usr/bin/bughfinder
