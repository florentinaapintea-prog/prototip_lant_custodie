"""
coc.py — Prototip de lanț de custodie verificabil criptografic pentru probe digitale.

Implementează modelul din secțiunea 5 a articolului:
  - achiziție: hash SHA-256 al imaginii (H0) + hash per fișier + rădăcină Merkle;
  - registru append-only: fiecare înregistrare conține hash-ul celei anterioare
    (h_i = H(h_{i-1} || r_i)), este semnată de operator și primește o marcă temporală
    de la un terț (aici SIMULAT printr-o cheie separată — nu este un serviciu RFC 3161
    sau o marcă temporală calificată eIDAS);
  - verificare independentă: lanț, semnături, mărci temporale, date.

Semnăturile folosesc Ed25519 (biblioteca `cryptography`) ca substitut pentru semnătura
electronică calificată; într-o implementare reală s-ar folosi certificate calificate
emise de un prestator de servicii de încredere.

Autori: F.-A. Pintea și coautor — cod de cercetare, nu pentru uz operațional.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CHUNK = 4 * 1024 * 1024  # 4 MiB, citire în flux


# --------------------------------------------------------------------------- hash
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.digest()


def canonical(obj: dict) -> bytes:
    """Serializare deterministă a unei înregistrări (chei sortate, fără spații)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ------------------------------------------------------------------------- Merkle
# Frunzele și nodurile interne au prefixe diferite (0x00 / 0x01), pentru a preveni
# atacurile de tip "second preimage" asupra arborelui (ca în RFC 6962).
def _leaf(h: bytes) -> bytes:
    return sha256(b"\x00" + h)


def _node(a: bytes, b: bytes) -> bytes:
    return sha256(b"\x01" + a + b)


def merkle_levels(leaf_hashes: list[bytes]) -> list[list[bytes]]:
    """Returnează toate nivelurile arborelui, de la frunze la rădăcină.
    Un nod fără pereche este promovat neschimbat la nivelul superior."""
    if not leaf_hashes:
        raise ValueError("arbore gol")
    level = [_leaf(h) for h in leaf_hashes]
    levels = [level]
    while len(level) > 1:
        nxt = [
            _node(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
            for i in range(0, len(level), 2)
        ]
        levels.append(nxt)
        level = nxt
    return levels


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    return merkle_levels(leaf_hashes)[-1][0]


def merkle_proof(levels: list[list[bytes]], index: int) -> list[tuple[str, bytes]]:
    """Dovada de apartenență pentru frunza `index`: lista (poziție, hash frate)."""
    proof = []
    for level in levels[:-1]:
        sib = index ^ 1
        if sib < len(level):
            proof.append(("L" if sib < index else "R", level[sib]))
        index //= 2
    return proof


def merkle_verify(file_hash: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    acc = _leaf(file_hash)
    for side, sib in proof:
        acc = _node(sib, acc) if side == "L" else _node(acc, sib)
    return acc == root


# ----------------------------------------------------------------------- actori
@dataclass
class Operator:
    """Persoană care efectuează operațiuni (procuror, polițist specializat, expert)."""
    nume: str
    calitate: str
    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def pub(self) -> Ed25519PublicKey:
        return self.key.public_key()


class TimestampAuthority:
    """Terț de marcare temporală — SIMULAT. Semnează (hash, timp) cu cheia proprie
    și impune timpi monotoni. Un serviciu real ar fi un TSA RFC 3161 / eIDAS."""

    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self._clock = 1_760_000_000  # ceas logic (secunde), pentru reproductibilitate

    @property
    def pub(self) -> Ed25519PublicKey:
        return self.key.public_key()

    def stamp(self, h: bytes) -> dict:
        self._clock += 1
        token = {"h": h.hex(), "t": self._clock}
        return {**token, "sig": self.key.sign(canonical(token)).hex()}


# ---------------------------------------------------------------------- registru
GENESIS_FIELDS = ("H0", "dosar")


class Ledger:
    """Registru de custodie append-only."""

    def __init__(self, dosar: str, h0: bytes, tsa: TimestampAuthority) -> None:
        self.dosar = dosar
        self.h0 = h0
        self.tsa = tsa
        self.entries: list[dict] = []

    @staticmethod
    def genesis(h0: bytes, dosar: str) -> bytes:
        return sha256(h0 + dosar.encode())  # h_0 = H(H0 || dosar)

    def head(self) -> bytes:
        return bytes.fromhex(self.entries[-1]["h"]) if self.entries else self.genesis(self.h0, self.dosar)

    def append(self, op: Operator, operatiune: str, instrument: str,
               hash_date: bytes, act: str) -> dict:
        r = {
            "nr": len(self.entries) + 1,
            "dosar": self.dosar,
            "act": act,
            "operator": f"{op.nume} ({op.calitate})",
            "operatiune": operatiune,
            "instrument": instrument,
            "hash_date": hash_date.hex(),
            "hash_anterior": self.head().hex(),
        }
        h_i = sha256(self.head() + canonical(r))  # h_i = H(h_{i-1} || r_i)
        entry = {
            "r": r,
            "h": h_i.hex(),
            "semnatura": op.key.sign(h_i).hex(),
            "marca_timp": self.tsa.stamp(h_i),
        }
        self.entries.append(entry)
        return entry


# --------------------------------------------------------------------- verificare
@dataclass
class Verdict:
    ok: bool
    motiv: str = ""


def verify_ledger(entries: list[dict], h0: bytes, dosar: str,
                  operator_keys: dict[str, Ed25519PublicKey],
                  tsa_pub: Ed25519PublicKey) -> Verdict:
    """Verificare independentă, fără încredere în cel care a ținut registrul.
    Are nevoie doar de: H0, identificatorul dosarului, cheile publice."""
    prev = Ledger.genesis(h0, dosar)
    last_t = -1
    for i, e in enumerate(entries, start=1):
        r = e["r"]
        if r["nr"] != i:
            return Verdict(False, f"numerotare întreruptă la poziția {i}")
        if r["dosar"] != dosar:
            return Verdict(False, f"înregistrarea {i} aparține altui dosar")
        if r["hash_anterior"] != prev.hex():
            return Verdict(False, f"legătura cu înregistrarea anterioară ruptă la {i}")
        h_i = sha256(prev + canonical(r))
        if h_i.hex() != e["h"]:
            return Verdict(False, f"conținutul înregistrării {i} a fost modificat")
        pub = operator_keys.get(r["operator"])
        if pub is None:
            return Verdict(False, f"operator necunoscut la {i}")
        try:
            pub.verify(bytes.fromhex(e["semnatura"]), h_i)
        except InvalidSignature:
            return Verdict(False, f"semnătura operatorului invalidă la {i}")
        ts = e["marca_timp"]
        if ts["h"] != e["h"]:
            return Verdict(False, f"marca temporală nu corespunde înregistrării {i}")
        try:
            tsa_pub.verify(bytes.fromhex(ts["sig"]), canonical({"h": ts["h"], "t": ts["t"]}))
        except InvalidSignature:
            return Verdict(False, f"marca temporală invalidă la {i}")
        if ts["t"] <= last_t:
            return Verdict(False, f"ordine temporală încălcată la {i}")
        last_t = ts["t"]
        prev = h_i
    return Verdict(True, "registru integru")


def verify_image(path: str, h0: bytes) -> Verdict:
    return Verdict(True, "imagine identică cu H0") if sha256_file(path) == h0 else \
        Verdict(False, "imaginea diferă de H0")


def file_hashes(blobs: Iterable[bytes]) -> list[bytes]:
    return [sha256(b) for b in blobs]
