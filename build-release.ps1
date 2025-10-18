 # Windows x86_64                                                                                                              
>> $env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="amd64"; go build -trimpath -ldflags "-s -w" -o dist\scanafile_windows_amd64\scanafile.exe .
>>
>> # Windows ARM64
>> $env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="arm64"; go build -trimpath -ldflags "-s -w" -o dist\scanafile_windows_arm64\scanafile.exe .
>>
>> # Linux x86_64
>> $env:CGO_ENABLED="0"; $env:GOOS="linux";   $env:GOARCH="amd64"; go build -trimpath -ldflags "-s -w" -o dist\scanafile_linux_amd64\scanafile .      
>>
>> # Linux ARM64 (Graviton)
>> $env:CGO_ENABLED="0"; $env:GOOS="linux";   $env:GOARCH="arm64"; go build -trimpath -ldflags "-s -w" -o dist\scanafile_linux_arm64\scanafile .      
>>
>> # macOS Intel
>> $env:CGO_ENABLED="0"; $env:GOOS="darwin";  $env:GOARCH="amd64"; go build -trimpath -ldflags "-s -w" -o dist\scanafile_darwin_amd64\scanafile .     
>>
>> # macOS Apple Silicon
>> $env:CGO_ENABLED="0"; $env:GOOS="darwin";  $env:GOARCH="arm64"; go build -trimpath -ldflags "-s -w" -o dist\scanafile_darwin_arm64\scanafile . 