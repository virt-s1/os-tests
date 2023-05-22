# add a user with passwd to allow login via password from console
# we do not change sshd setting if it forbidden password access for security reason 
# example of called by os-tests: --case_setup "/tmp/debug_enable_user_with_passwd.sh $testuser $password"
# or --case_setup "/tmp/debug_enable_user_with_passwd.sh"
set -x
user=$1
password=$2
if [ -z $user ] ||  [ -z $password ]; then
    echo "user or password missing, will auto generate one"
    user="testrh$$"
    password=$(openssl rand -base64 8)
fi

sudo egrep "$user|testrh" /etc/passwd
if [ $? -eq 0 ]; then
    echo "$user or user started with testrh already exists, exit!"
    exit 0
fi
sudo useradd $user
sudo bash -c "echo $password|passwd $user --stdin"
sudo usermod -aG wheel $user