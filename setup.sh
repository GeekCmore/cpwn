#/bin/sh
echo "Start setup!"
pip install -r requirements.txt
sudo apt-get install patchelf
mkdir -p ~/.config/cpwn
cp config.json ~/.config/cpwn/
cp template.py ~/.config/cpwn/exp_template.py
cp -r ./kernel_exploit ~/.config/cpwn/kernel_exploit
chmod +x cpwn.py
echo "Move cpwn to /usr/bin"
sudo cp cpwn.py /usr/bin/cpwn
cpwn
