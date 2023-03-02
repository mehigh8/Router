<b>Rosu Mihai Cosmin 323CA</b>

<b>ARP:</b>
- Atunci cand receptionez un pachet de tip ARP request pe broadcast, verific
daca are ca destinatie adresa IP a router-ului, caz in care trimit un ARP
replay inapoi, actualizand adresa MAC sursa (care inainte are destinatie, si
era broadcast).
- Atunci cand receptionez un pachet de tip ARP reply, verific daca are ca
destinatie adresa IP a router-ului, caz in care verific daca in cache (vectorul
static de arp_entry-uri) mai am adresa IP de pe care a venit pachetul. Daca o
mai am, atunci trec la urmatorul pachet. Altfel, adaug o noua intrare in cache
si parcurg coada de pachete pentru a vedea daca sunt pachete care asteapta sa
fie trimise spre IP-ul nou gasit, trimitandu-le in acest caz, deoarece acum
stiu adresa MAC a destinatiei. Pentru cele care nu trebuie trimise spre acest
IP, le adaug intr-o noua coada.

<b>Forward:</b>
- Atunci cand receptionez un pachet de tip IPv4, verific daca pachetul este
receptionat corect (daca adresa MAC a interfetei este si cea destinatie din
header-ul de Ethernet). Apoi, verific daca pacheetul IPv4 este de tip ICMP,
caz in care ma intereseaza daca este de tip echo request si daca adresa IP
destinatie este cea a router-ului. In acest caz, trimit inapoi acelasi pachet,
dar cu tipul ICMP-ului schimbat in echo reply. Altfel, continui prin a verifica
checksum-ul si daca este incorect voi arunca pachetul. Altfel, verific daca
pachetul are ttl-ul mai mare de 1. Daca nu il are, voi trimite inapoi un pachet
ICMP de tip Time exceeded. Daca are ttl-ul indeajuns de mare, voi cauta ruta pe
care trebuie sa trimit mai departe pachetul. Daca nu este gasita nicio ruta,
voi trimite inapoi un pachet ICMP de tip Host unreachable. Daca gasesc o ruta,
am nevoie de adresa MAC a next hop-ului, prin urmare caut in cache-ul de ARP.
Daca nu gasesc nicio potrivire, inseamna ca trebuie sa trimit un ARP request
catre next hop. Prin urmare, nu pot sa trimit inca pachetul, deci il voi pune
in coada, cu toate campurile pregatite, inafara de adresa MAC destinatie. In
schimb, daca gasesc adresa MAC cautata, pot actualiza ttl-ul si checksum-ul,
adresele MAC si interfata si pot trimite pachetul.

<b>Coada de pachete:</b>
- Pentru coada am folosit queue-ul din schelet, dar am retinut in el adrese
catre o structura (struct unsent) care contine pachetul si adresa IP s next
hopului, pentru a nu cauta de doua ori cea mai buna ruta.

<b>Longest Prefix Match:</b>
- Pentru a implementa eficient cautarea celei mai bune rute (LPM) am folosit
un trie, a carui implementare am pus-o in skel.h, respectiv in skel.c.
- Trie-ul implementat de mine foloseste structura node, care contine un
pointer de tip void, route (folosit pentru a pointa spre o intrare din tabela
de rutare), si doi fii, zero (corespunde daca bitul e 0) si one (corespunde
daca bitul e 1).
- Am implementat 3 functii:
  - create_node - Aloca memorie pentru un nod si ii seteaza pointerul route pe
 adresa primita ca parametru.
  - add_route - Pentru o intrare din tabela de rutare, parcurge trie-ul bit cu
 bit dupa prefix (de la stanga la dreapta) cat timp masca nu este 0. Nodul la
 care masca ajunge sa fie 0, va retine adresa tabelei de rutare.
  - search_route - Parcurge trie-ul bit cu bit dupa adresa IP cautata (de la
 dreapta la stanga) pana cand ajung la o frunza. Pe parcursul cautarii, de
 fiecare data cand gasesc un nod care retine o ruta, retin aceasta ruta, iar 
 in final returnez ultima ruta gasita.
- Inainte sa incep primirea de pachete, pentru fiecare intrare din tabela de
rutare, apelez functia add_route, iar atunci cand caut ruta pentru un pachet
apelez search_route.

<b>ICMP:</b>
- In cazul in care un pachet ramane fara timp (ttl mai mic decat 1) sau pentru
un pachet nu se gaseste nicio ruta, trebuie sa trimit inapoi un pachet ICMP
corespunzator (Time exceeded, respectiv Host unreachable).
- De asemenea, inainte sa pun header-ul ICMP in payload-ul pachetului, retin
primii 64 de octetii de dupa header-ul IP, iar dupa ce pun header-ul ICMP pun
si acesti 64 de octeti.
- Cazul pentru echo request l-am mentionat in sectiunea de Forward.

<b>Bonus:</b>
- Am implementat actualizarea sumei de control incrementale, folosind formula
din RFC 1624: new_check = ~(~prev_check + ~prev_ttl + new_ttl) - 1. Acest -1 de
la sfarsit este adaugat de mine, deoarece dupa ce am calculat checksum-ul prin
ambele metode, mereu cel incremental era mai mare cu 1.
