wget https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz
tar -xvzf emerging.rules.tar.gz
wget https://rules.emergingthreats.net/open/suricata-4.0/SID-Descriptions-ETOpen.json.gz
gunzip SID-Descriptions-ETOpen.json.gz
mv SID-Descriptions-ETOpen.json rules/
cp documentator.py rules/
cp inventator.py rules/
cd rules/
for f in *.rules; do python3 documentator.py $f > $f.md; done
for f in *.rules; do python3 inventator.py $f >> recensement.md; done
rm ~/doc/*.md
mv *.md > ~/doc/
cd ~/doc/
echo "Ce repertoire reprend la documentation des règles Suricata 4 Emerging Threats Open, classées par fichier de règles">readme.md
for f in *.md; do echo "["$f"]("$f")" >> readme.md; echo " ">> readme.md; done
git add .
git commit -m "Commit automatique"
git push -u origin master
