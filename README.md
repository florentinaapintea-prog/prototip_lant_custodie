# Prototip: lanț de custodie verificabil criptografic pentru probe digitale

Cod de cercetare care însoțește articolul *Probele digitale în procesul penal român* (secțiunea 5).
Nu este destinat utilizării operaționale.

## Conținut

| Fișier | Rol |
| --- | --- |
| `coc.py` | modelul: hash SHA-256, arbore Merkle, registru înlănțuit, semnături, mărci temporale, verificare |
| `experiments.py` | experimentele (a)–(d) din secțiunea 5.8 |
| `results/` | rezultatele brute (`rezultate.json` și câte un `.csv` pentru fiecare experiment) |

## Rulare

```bash
pip install cryptography          # testat cu cryptography 50.0.1, Python 3.13
python3 experiments.py --out results
python3 experiments.py --quick    # variantă scurtă, aprox. 10 s
```

Seed-ul este fix (`20261021`), deci datele de test și scenariile de alterare se reproduc identic.
Timpii depind de mașină și trebuie raportați împreună cu configurația din `rezultate.json → mediu`.

## Experimente

- **(a) Detectarea alterărilor:** 13 scenarii × 1.000 de încercări. Printre ele: modificarea unui bit în imagine sau într-un fișier, modificarea, ștergerea, inversarea și inserarea de înregistrări, trunchierea registrului, rescrierea prin înțelegere frauduloasă, semnăturile false și antedatarea.
- **(b) Costul suplimentar cu disc:** achiziția obișnuită (copie bit cu bit + SHA-256, o singură trecere) comparată cu achiziția din model (aceeași trecere, plus hash per fișier, arbore Merkle și 6 înregistrări în registru). Imagini de 256 MiB, 1 GiB și 4 GiB, câte 11 repetări în ordine alternată, cu raportarea medianei și a IQR.
- **(b2) Costul suplimentar doar de calcul:** aceleași operații, cu datele deja în memorie (256 MiB și 1 GiB), câte 11 repetări după o rulare de încălzire.
- **(c) Verificarea registrului:** registre de 10 până la 10.000 de înregistrări, 5 repetări.
- **(d) Dovezile Merkle:** de la 100 la 1.000.000 de fișiere, câte 1.000 de dovezi aleatorii.

## Limitări (de menționat în articol)

1. Datele de test sunt sintetice (octeți aleatori), nu imagini reale de telefoane sau discuri.
2. Ed25519 înlocuiește semnătura electronică calificată. Certificatele calificate eIDAS și dispozitivele securizate (QSCD) nu sunt modelate, iar o semnătură calificată reală este mai lentă.
3. Serviciul de marcare temporală este **simulat** cu o cheie locală, nu prin RFC 3161 sau eIDAS. Latența de rețea a unui TSA real nu este inclusă.
4. Implementarea este în Python pur. Un instrument operațional (C/Rust, hash paralel) ar avea un cost suplimentar mai mic.
5. Timpii de achiziție sunt măsurați cu fișierul sursă în memoria cache a sistemului de operare, adică într-un scenariu favorabil pentru citire. Pe un disc real, citirea domină, iar costul relativ al modelului scade.
