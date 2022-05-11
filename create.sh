#!/bin/bash
#!/bin/bash  
userfile=./create.txt

username=$(cat ./create.txt | tr 'A-Z'  'a-z')

for user in $username
do
  if [[  -f /etc/lsb-release   && $(cat /etc/passwd | grep -c $user) -eq 0 ]]; then
       #adding users '$user' is a variable that changes
       #usernames accordingly in txt file.
       echo $user  
       adduser $user --gecos "Ricky Beaty,NA,NA,NA" --disabled-password
       passwd -d $user
       su -c "mkdir /home/$user/.ssh" $user
       su -c "chmod 700 /home/$user/.ssh" $user
       su -c  "touch /home/$user/.ssh/authorized_keys" $user
       echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUzKa6Tb2hBp0oBxC4I1HmCJaGBGkWybfKSmL34THhOMYYPGqsdwYszRPJEkeVTOaKYwE6S9AoKewUFOGtJZt/Djzi3KKzBO7ZRsJho+v7Ifxl34le4Gf77c3cI2NvNMrAMWL2+ObPXUxpplzuOox7SyPWudCEUy4a5F1vChNQm/4EkJ+57LSeFUGR/N1+rNcdYpuAiQFtQsIlXUedj6+T0ujvEDutXcSM5uh6JZA2lz4qy9MfU0eOuDWtlbjZzHlCFmxobQNEqW4AU9I2kBXrXBFhBLHEa1y0mBxZxdN8ohEesEgJvzrEYNG29hLpd3D6QKoAJzLTBiQRdQ7JhM41 BEATYCONSULTANC\dhaval@a-l9y4imjucnkl" >> /home/$user/.ssh/authorized_keys
       sudo chmod 600 /home/$user/.ssh/authorized_keys
       echo "$user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users
    if [ -f /etc/redhat-release  ]; then
        adduser $user
        usermod -aG wheel $user
        su -c 'mkdir /home/$user/.ssh' $user
        su -c 'chmod 700 /home/$user/.ssh' $user
        su -c 'touch /home/$user/.ssh/authorized_keys' $user
        curl https://bc-public.s3.eu-west-2.amazonaws.com/$user.pub >> /home/$user/.ssh/authorized_keys
        chmod 600 /home/$user/.ssh/authorized_keys
        echo "$user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users
    else
        echo "$user alredy exist"
      fi
  else
      echo "$user alredy exist"
   fi
done



