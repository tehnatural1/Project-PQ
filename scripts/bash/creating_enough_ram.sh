sudo fallocate -l 64G ~/swapfile
sudo chmod 0600 ~/swapfile
sudo mkswap ~/swapfile
sudo swapon ~/swapfile
