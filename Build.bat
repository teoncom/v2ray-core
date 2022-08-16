set GOOS=windows
set CGO_ENABLED=1
set GOARCH=amd64
go mod tidy
go build -a -trimpath -asmflags "-s -w" -ldflags "-s -w -buildid=" -buildmode=c-shared -o "..\..\release\v2ray-sn.dll" ".\main"
pause