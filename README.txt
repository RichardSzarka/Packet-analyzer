Na spustenie programu budete potrebovat modul SCAPY.

Priložil som aj virtuálne prostredie v ktorom som pracoval ( v priečinku virtualenv )

Ak vam prostredie nejde spustit tak mozete si modul SCAPY nainstalovat prikazom:

pip install scapy

alebo

pip install -r requirements.txt   (v tomto súbore)

-----------------------------------------------------------------------------------

Program spustite príkazom v terminály:

python main.py

-----------------------------------------------------------------------------------

Program sa vás spýta aký súbor chcete načítať. Súbor musí byť v rovnakom priečinku 
ako komponenty programu a píšte názov bez .pcap prípony (eth-2 -> NIE eth-2.pcap)

Ďalej sa vás spýta či chcete zapísať výpisy do output.txt (ak je výpis moc velký
a nezmestí sa do terminálu tak je lepšie tak spraviť)

1 -> áno
0 -> nie

Ďalej už prepínačmi 1 až 10 vypíšete buď všetky rámce (1) alebo konkrétne komunikácie
(2-10)

Prepínačom change zmeníte pcap súbor

Prepínačom end ukončíte program