#!/usr/bin/env bash
# Guided demo of the secure gateway: upload / status / cancel / download,
# plus fault injection (reorder, delay, drop) through the adapter control API.
set -u
API=${API:-http://127.0.0.1:8000}
CTL=${CTL:-http://127.0.0.1:8080}
HERE=$(cd "$(dirname "$0")/.." && pwd)

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
json() { python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d,indent=2))" 2>/dev/null || cat; }
fid()  { python3 -c "import sys,json;print(json.load(sys.stdin)['id'])"; }

say "1. clean upload -> wait -> download"
RESP=$(curl -s -F "file=@$HERE/samples/clean.txt" "$API/files"); echo "$RESP" | json
ID=$(echo "$RESP" | fid); sleep 1
curl -s "$API/files/$ID" | json
echo "-- download:"; curl -s "$API/files/$ID/download"; echo

say "2. harmless hit sample (EICAR) -> infected -> download denied"
RESP=$(curl -s -F "file=@$HERE/samples/eicar.txt" "$API/files"); echo "$RESP" | json
ID=$(echo "$RESP" | fid); sleep 1
curl -s "$API/files/$ID" | json
echo "-- download attempt:"; curl -s -w " [HTTP %{http_code}]\n" "$API/files/$ID/download"

say "3. slow scanner: 4 in flight -> 5th gets 503"
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"delay_min_ms":2000,"delay_max_ms":2000}' > /dev/null
for i in 1 2 3 4; do curl -s -F "file=@$HERE/samples/clean.txt;filename=busy$i.txt" "$API/files" > /dev/null & done
sleep 0.5
curl -s -w " [HTTP %{http_code}]\n" -F "file=@$HERE/samples/clean.txt;filename=too-many.txt" "$API/files"
wait

say "4. cancel an on-the-wire scan (reply is discarded, slot held until then)"
RESP=$(curl -s -F "file=@$HERE/samples/clean.txt;filename=cancelme.txt" "$API/files")
ID=$(echo "$RESP" | fid)
curl -s -X POST "$API/files/$ID/cancel" | json
sleep 3   # held reply arrives and is discarded, slot released
curl -s "$API/files/$ID" | json

say "5. 5s total deadline: scanner slower than 5s -> failed, link recycled"
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"delay_min_ms":10000,"delay_max_ms":10000}' > /dev/null
RESP=$(curl -s -F "file=@$HERE/samples/clean.txt;filename=toolate.txt" "$API/files")
ID=$(echo "$RESP" | fid)
echo "waiting for the 5s deadline..."; sleep 6
curl -s "$API/files/$ID" | json
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"delay_min_ms":0,"delay_max_ms":300}' > /dev/null
sleep 1
RESP=$(curl -s -F "file=@$HERE/samples/clean.txt;filename=after-timeout.txt" "$API/files")
ID=$(echo "$RESP" | fid); sleep 1
echo "-- service recovered on a fresh connection:"; curl -s "$API/files/$ID" | json

say "6. connection drop: unfinished scans fail, then auto-reconnect"
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"drop_after_replies":1,"delay_min_ms":0,"delay_max_ms":0}' > /dev/null
curl -s -F "file=@$HERE/samples/clean.txt;filename=drop-a.txt" "$API/files" > /tmp/demo-a.json &
curl -s -F "file=@$HERE/samples/clean.txt;filename=drop-b.txt" "$API/files" > /tmp/demo-b.json &
wait
IDA=$(fid < /tmp/demo-a.json); IDB=$(fid < /tmp/demo-b.json); sleep 1
curl -s "$API/files/$IDA" | json; curl -s "$API/files/$IDB" | json
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"drop_after_replies":0}' > /dev/null
sleep 1
RESP=$(curl -s -F "file=@$HERE/samples/clean.txt;filename=after-drop.txt" "$API/files")
ID=$(echo "$RESP" | fid); sleep 1
echo "-- recovered:"; curl -s "$API/files/$ID" | json

say "7. out-of-order replies (random 0-2s delay window)"
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"delay_min_ms":0,"delay_max_ms":2000}' > /dev/null
IDS=""
for i in 1 2 3 4; do
  RESP=$(curl -s -F "file=@$HERE/samples/clean.txt;filename=ooo$i.txt" "$API/files")
  IDS="$IDS $(echo "$RESP" | fid)"
done
sleep 3
for ID in $IDS; do curl -s "$API/files/$ID" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['filename'],d['status'])"; done
curl -s -X POST "$CTL/config" -H 'Content-Type: application/json' \
  -d '{"delay_min_ms":0,"delay_max_ms":300}' > /dev/null

say "done. adapter behaviour config: curl $CTL/config"
