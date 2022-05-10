userfile= delete.txt

username=$(cat delete.txt | tr 'A-Z'  'a-z')

for user in $username
do
       # adding users '$user' is a variable that changes
       # usernames accordingly in txt file.
       deluser $user
done

echo "$(wc -l delete.txt) users have been created" 
