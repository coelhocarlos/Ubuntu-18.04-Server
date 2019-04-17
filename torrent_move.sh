#!/bin/bash
# diretorio para fazer a busca
dir="/home/zombie/apps/torrent/torrent-down"
# diretorio para enviar os arquivos
iso="/home/zombie/games/instalacao"
rar="/home/zombie/apps/download"

# a script to recursively find and copy files to a desired location
find $dir -type f -iname '*.iso' -print0 |
while IFS= read -r -d '' f; 
do mv -- "$f" $iso ;

find $dir -type f -iname '*.rar *.exe *.zip' -print0 |
while IFS= read -r -d '' f; 
do mv -- "$f" $rar ;
done
