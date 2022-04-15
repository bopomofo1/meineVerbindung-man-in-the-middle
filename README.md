# meineVerbindung

## Anforderungen

 - sudo apt-get install -y libnet-dev 
 - sudo apt-get install libpcap-dev
 - mininet

## ToDo

einschleusen von Nachrichten in unverschlüsselte TCP-Verbindungen


- [X] MAC-Addressen durch ARP-Requests herausfinden
- [X] ARP-Poisoning starten
- [X] Pakete empfangen
- [X] gefälschte TCP-Pakete senden
- [ ] Entscheiden an wenn man das Paket schicken möchte
- [ ] desynchrone Sequenznummern synchronisieren

## Kompilieren

make

## Ausführen

IP-Weiterleiten für den MITM aktivieren 
    sysctl -w net.ipv4.ip_forward=1

Mininet Netzwerk starten
    sudo mn --custom project.py --topo=project