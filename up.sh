#!/bin/bash
# מזגן - עדכון השרת. ב-Cloud Shell:  curl -sL elior-sasi.github.io/kor/up.sh | bash
set -e
P=tab-fd9b6; R=europe-west1; B=https://elior-sasi.github.io/kor
mkdir -p ~/k && cd ~/k
echo "▶ מוריד קוד..."
curl -fsSL "$B/srv-main.py?$(date +%s)" -o main.py
curl -fsSL "$B/srv-req.txt?$(date +%s)" -o requirements.txt
printf 'venv/\n*.sh\n' > .gcloudignore
[ -s .tick ] || (head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32 > .tick)
T=$(cat .tick)
gcloud config set project $P >/dev/null 2>&1
echo "▶ מפעיל תזמון בגוגל..."
gcloud services enable cloudscheduler.googleapis.com --quiet
echo "▶ מעלה את השרת (2-4 דקות)..."
gcloud functions deploy kor --gen2 --runtime=python312 --region=$R --source=. --entry-point=kor \
  --trigger-http --allow-unauthenticated --memory=256Mi --set-env-vars=TICK_SECRET=$T --quiet >/dev/null
URL=$(gcloud functions describe kor --region=$R --format='value(url)')
echo "▶ קובע ריצה כל דקה..."
if gcloud scheduler jobs describe kor-tick --location=$R >/dev/null 2>&1; then
  gcloud scheduler jobs update http kor-tick --location=$R --schedule="* * * * *" --uri="$URL/tick" \
    --http-method=POST --update-headers="X-Tick=$T" --quiet >/dev/null
else
  gcloud scheduler jobs create http kor-tick --location=$R --schedule="* * * * *" --time-zone=Asia/Jerusalem \
    --uri="$URL/tick" --http-method=POST --headers="X-Tick=$T" --quiet >/dev/null
fi
echo ""
echo "✅ הכול מוכן"
