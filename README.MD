# File system scan without agent - DEMO


PS C:\Users\Tom\Documents\code\scanafile> .\scanafile.exe `
>>     --path . `
>>   --passwords-url https://raw.githubusercontent.com/sabixx/cert-file-scan/master/pwd-list.txt
>>



## Install keytool
It shows a warning that keytool is missing. I don't want to install keytool... 
...Great :-) . Well, then don't install it. When keytool is missing it's unlikley that anything on this box is using a java keystore...

###Amazon Linux 2023
´´´
sudo dnf install -y java-17-amazon-corretto   # or: java-17-openjdk
keytool -version
´´´

###Amazon Linux 2
´´´
sudo yum install -y java-11-amazon-corretto-headless   # or: java-11-openjdk-headless
keytool -version
´´´

###Ubuntu/Debian
´´´
sudo apt-get update
sudo apt-get install -y openjdk-17-jre-headless   # or: openjdk-11-jre-headless
keytool -version
´´´

###RHEL/CentOS
´´´
sudo yum install -y java-17-openjdk   # or: java-11-openjdk
keytool -version
´´´

###SUSE
´´´
sudo zypper install -y java-17-openjdk
keytool -version
´´´
