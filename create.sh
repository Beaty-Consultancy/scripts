userfile= create.txt

username=$(cat create.txt | tr 'A-Z'  'a-z')

for user in $username
do
       #adding users '$user' is a variable that changes
       #usernames accordingly in txt file.
       sudo useradd $user
       adduser $user --gecos "Ricky Beaty,NA,NA,NA" --disabled-password
       su -c 'mkdir /home/$user/.ssh' $user
       su -c 'chmod 700 /home/$user/.ssh' $user
       su -c 'touch /home/$user/.ssh/authorized_keys' $user
       curl https://bc-public.s3.eu-west-2.amazonaws.com/$user.pub >> /home/$user/.ssh/authorized_keys
       chmod 600 /home/$user/.ssh/authorized_keys
       echo "$user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users
done

echo "$(wc -l create.txt) users have been created" 



