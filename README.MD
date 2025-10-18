# File system scan without agent - DEMO


### Run on all taged systems 
´´´
aws ssm send-command \
  --document-name "AWS-RunRemoteScript" \
  --targets "Key=tag:Scanafi-filebased,Values=yes,true,enabled,1" \
  --parameters '{
    "sourceType":["GitHub"],
    "sourceInfo":["{\"owner\":\"sabixx\",\"repository\":\"cert-file-scan\",\"path\":\"file-scan-nix\",\"getOptions\":\"branch:main\"}"],
    "commandLine":["bash ./file-scan-nix \"/opt/projects\""],
    "executionTimeout":["3600"]
  }' \
  --comment "Run file-scan-nix on Filebased-tagged instances" \
  --max-concurrency "50" \
  --max-errors "0"
´´´

### Windows tagged
´´´
aws ssm send-command `
  --document-name "AWS-RunRemoteScript" `
  --targets "Key=tag:Scanafi-filebased,Values=yes,true,enabled,1" `
  --parameters '{
    "sourceType":["GitHub"],
    "sourceInfo":["{\"owner\":\"sabixx\",\"repository\":\"cert-file-scan\",\"path\":\"file-scan-win.ps1\",\"getOptions\":\"branch:main\"}"],
    "commandLine":["powershell -NoProfile -ExecutionPolicy Bypass -File .\\file-scan-win.ps1 -Path \"D:\\\\data\""],
    "executionTimeout":["3600"]
  }' `
  --comment "Run file-scan-win on Filebased-tagged instances" `
  --max-concurrency "50" `
  --max-errors "0"
´´´

### with instance ID
´´´
aws ssm send-command \
  --document-name "AWS-RunRemoteScript" \
  --instance-ids i-019b5adb8f6223d4d \
  --parameters '{
    "sourceType":["GitHub"],
    "sourceInfo":["{\"owner\":\"sabixx\",\"repository\":\"cert-file-scan\",\"path\":\"file-scan-nix\",\"getOptions\":\"branch:main\"}"],
    "commandLine":["bash ./file-scan-nix \"/var/www/app\""],
    "executionTimeout":["3600"]
  }' \
  --comment "file-scan-nix one-time run with path"
´´´

´´´
aws ssm send-command `
  --document-name "AWS-RunRemoteScript" `
  --instance-ids i-0123456789abcdef0 `
  --parameters '{
    "sourceType":["GitHub"],
    "sourceInfo":["{\"owner\":\"sabixx\",\"repository\":\"cert-file-scan\",\"path\":\"file-scan-win.ps1\",\"getOptions\":\"branch:main\"}"],
    "commandLine":["powershell -NoProfile -ExecutionPolicy Bypass -File .\\file-scan-win.ps1 -Path \"D:\\\\data\\\\certs with spaces\""],
    "executionTimeout":["3600"]
  }' `
  --comment "file-scan-win one-time run with path"
´´´


##Install keytool
It shows a warning that keytool is missing. I don't want to install keytool... 
...Great :-) . Well, then don't install it. When keytool is missing it's highly unlikley that anything on this box is using a java keystore...

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