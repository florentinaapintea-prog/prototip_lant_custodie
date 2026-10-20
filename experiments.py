"""
experiments.py — experimentele (a)–(d) din secțiunea 5.8 a articolului.

  (a) detectarea alterărilor provocate intenționat;
  (b) costul suplimentar al mecanismului față de o achiziție obișnuită (copie + SHA-256);
  (c) timpul de verificare a registrului pentru instanță / apărare;
  (d) dimensiunea și costul dovezilor Merkle în funcție de numărul de fișiere.

Toate datele de test sunt SINTETICE (octeți aleatori generați cu seed fix).
Rulare:  python3 experiments.py --out results
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import sys
import time

import cryptography

import coc

SEED = 20261021
REPS = 5
REPS_IO = 11      # achiziția cu disc este zgomotoasă: mai multe repetări
REPS_CPU = 11


def median_iqr(xs: list[float]) -> dict:
    xs = sorted(xs)
    q = statistics.quantiles(xs, n=4) if len(xs) >= 2 else [xs[0]] * 3
    return {"median": statistics.median(xs), "q1": q[0], "q3": q[2], "n": len(xs)}


# ------------------------------------------------------------ date de test
def make_evidence(path: str, size: int, mean_file: int, rng: random.Random) -> list[tuple[int, int]]:
    """Scrie o 'imagine de disc' sintetică și întoarce extinderile (offset, lungime)
    ale fișierelor din ea. Între fișiere rămâne spațiu 'nealocat' (tot aleator)."""
    extents, off = [], 0
    while True:
        ln = max(1, int(rng.expovariate(1 / mean_file)))
        gap = rng.randint(0, 4096)
        if off + gap + ln > size:
            break
        extents.append((off + gap, ln))
        off += gap + ln
    with open(path, "wb") as f:
        remaining = size
        while remaining:
            n = min(coc.CHUNK, remaining)
            f.write(rng.randbytes(n))
            remaining -= n
    return extents


# ---------------------------------------------------------- achiziție
def acquire_baseline(src: str, dst: str) -> bytes:
    """Practica obișnuită: copie bit cu bit + SHA-256 al imaginii, într-o singură trecere."""
    h = hashlib.sha256()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while chunk := fi.read(coc.CHUNK):
            h.update(chunk)
            fo.write(chunk)
        fo.flush()
        os.fsync(fo.fileno())
    return h.digest()


def acquire_model(src: str, dst: str, extents: list[tuple[int, int]]) -> tuple[bytes, list[bytes]]:
    """Modelul propus: aceeași trecere unică, dar calculează în plus hash-ul fiecărui
    fișier (pentru arborele Merkle), fără a reciti datele."""
    h = hashlib.sha256()
    hashers = [hashlib.sha256() for _ in extents]
    k, pos = 0, 0  # k = primul fișier încă neterminat
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while chunk := fi.read(coc.CHUNK):
            h.update(chunk)
            fo.write(chunk)
            mv = memoryview(chunk)  # fără copii suplimentare ale datelor
            end = pos + len(chunk)
            j = k
            while j < len(extents) and extents[j][0] < end:
                s, ln = extents[j]
                a, b = max(s, pos), min(s + ln, end)
                if a < b:
                    hashers[j].update(mv[a - pos:b - pos])
                if s + ln <= end:
                    if j == k:
                        k += 1
                    j += 1
                else:
                    break
            pos = end
        fo.flush()
        os.fsync(fo.fileno())
    return h.digest(), [x.digest() for x in hashers]


def typical_chain(ledger: coc.Ledger, ops: dict, root: bytes, h0: bytes) -> None:
    """Șase operațiuni tipice ale unei percheziții informatice."""
    p, e, j = ops["procuror"], ops["expert"], ops["grefier"]
    ledger.append(p, "achiziție imagine forensică", "acq-proto 1.0", h0, "mandat JDL nr. X/2026")
    ledger.append(p, "înregistrare rădăcină Merkle a fișierelor", "acq-proto 1.0", root, "mandat JDL nr. X/2026")
    ledger.append(e, "copie de lucru pentru expertiză", "acq-proto 1.0", h0, "ordonanță expertiză")
    ledger.append(e, "analiză pe copie", "analiza-proto 1.0", h0, "ordonanță expertiză")
    ledger.append(e, "predare raport de expertiză", "analiza-proto 1.0", h0, "ordonanță expertiză")
    ledger.append(j, "primire suport la grefa instanței", "-", h0, "rechizitoriu")


def make_operators() -> dict[str, coc.Operator]:
    return {
        "procuror": coc.Operator("P. Popescu", "procuror"),
        "expert": coc.Operator("E. Ionescu", "expert tehnic"),
        "grefier": coc.Operator("G. Marin", "grefier"),
    }


def pubkeys(ops: dict[str, coc.Operator]) -> dict:
    return {f"{o.nume} ({o.calitate})": o.pub for o in ops.values()}


# ------------------------------------------------- (a) detectare alterări
def exp_tamper(workdir: str, rng: random.Random, trials: int = 1000) -> list[dict]:
    img = os.path.join(workdir, "tamper.img")
    extents = make_evidence(img, 64 * 2**20, 64 * 1024, rng)
    h0 = coc.sha256_file(img)
    with open(img, "rb") as f:
        data = bytearray(f.read())
    blobs = [bytes(data[s:s + ln]) for s, ln in extents]
    fh = coc.file_hashes(blobs)
    levels = coc.merkle_levels(fh)
    root = levels[-1][0]

    ops = make_operators()
    tsa = coc.TimestampAuthority()
    led = coc.Ledger("dosar 123/P/2026", h0, tsa)
    typical_chain(led, ops, root, h0)
    for i in range(14):  # registru de 20 de înregistrări
        led.append(ops["expert"], f"operațiune suplimentară {i}", "analiza-proto 1.0", h0, "ordonanță expertiză")
    base = led.entries
    keys = pubkeys(ops)
    assert coc.verify_ledger(base, h0, led.dosar, keys, tsa.pub).ok
    anchored_head = base[-1]["h"]  # valoarea depusă periodic la un terț (secț. 5.6)

    rows = []

    def record(name: str, desc: str, detected: int, n: int, note: str = "") -> None:
        rows.append({"scenariu": name, "descriere": desc, "incercari": n,
                     "detectate": detected, "rata": detected / n, "nota": note})

    # T1: un octet modificat în imagine
    det = 0
    for _ in range(trials):
        pos = rng.randrange(len(data))
        old = data[pos]
        data[pos] = old ^ (1 << rng.randrange(8))
        det += hashlib.sha256(data).digest() != h0
        data[pos] = old
    record("T1", "un bit modificat în imaginea forensică", det, trials)

    # T2: un bit modificat într-un fișier prezentat în dosar cu dovadă Merkle
    det = 0
    for _ in range(trials):
        i = rng.randrange(len(blobs))
        b = bytearray(blobs[i])
        p = rng.randrange(len(b))
        b[p] ^= 1 << rng.randrange(8)
        det += not coc.merkle_verify(coc.sha256(bytes(b)), coc.merkle_proof(levels, i), root)
    record("T2", "un bit modificat într-un fișier depus cu dovadă Merkle", det, trials)

    # T2b: fișier străin (care nu provine din imagine) prezentat cu dovada altui fișier
    det = 0
    for _ in range(trials):
        i = rng.randrange(len(blobs))
        fake = rng.randbytes(len(blobs[i]))
        det += not coc.merkle_verify(coc.sha256(fake), coc.merkle_proof(levels, i), root)
    record("T2b", "fișier străin prezentat drept provenind din imagine", det, trials)

    fields = ["act", "operator", "operatiune", "instrument", "hash_date"]

    def check(es: list[dict]) -> bool:
        return not coc.verify_ledger(es, h0, led.dosar, keys, tsa.pub).ok

    # T3: modificarea unui câmp dintr-o înregistrare
    det = 0
    for _ in range(trials):
        es = copy.deepcopy(base)
        e = rng.choice(es)
        f = rng.choice(fields)
        e["r"][f] = e["r"][f] + " [modificat]" if f != "hash_date" else "00" * 32
        det += check(es)
    record("T3", "modificarea unui câmp într-o înregistrare (ex. versiunea instrumentului)", det, trials)

    # T4: ștergerea unei înregistrări
    det = 0
    for _ in range(trials):
        es = copy.deepcopy(base)
        del es[rng.randrange(len(es) - 1)]  # orice înregistrare, mai puțin ultima
        det += check(es)
    record("T4", "ștergerea unei înregistrări intermediare", det, trials)

    # T4b: trunchierea registrului (ștergerea ultimelor înregistrări)
    det_internal = det_anchor = 0
    for _ in range(trials):
        k = rng.randint(1, len(base) - 1)
        es = copy.deepcopy(base[:-k])
        det_internal += check(es)
        det_anchor += check(es) or es[-1]["h"] != anchored_head
    record("T4b", "trunchierea registrului — doar verificare internă", det_internal, trials,
           "o trunchiere lasă un registru intern coerent")
    record("T4c", "trunchierea registrului — cu valoarea finală ancorată la terț", det_anchor, trials)

    # T5: inversarea a două înregistrări consecutive
    det = 0
    for _ in range(trials):
        es = copy.deepcopy(base)
        i = rng.randrange(len(es) - 1)
        es[i], es[i + 1] = es[i + 1], es[i]
        det += check(es)
    record("T5", "inversarea ordinii a două înregistrări", det, trials)

    # T6: inserare retroactivă de către un operator care are DOAR propria cheie
    det = 0
    for _ in range(trials):
        k = rng.randrange(1, len(base))
        forged = coc.Ledger(led.dosar, h0, tsa)
        forged.entries = copy.deepcopy(base[:k])
        forged.append(ops["expert"], "operațiune inserată retroactiv", "x", h0, "x")
        tail = copy.deepcopy(base[k:])  # restul rămân semnate de operatorii reali
        es = forged.entries + tail
        det += check(es)
    record("T6", "inserare retroactivă de un singur operator (doar cheia proprie)", det, trials)

    # T7: înțelegere frauduloasă — atacatorul deține TOATE cheile operatorilor și obține
    #     mărci temporale noi pentru întregul registru rescris
    det_internal = det_anchor = 0
    for _ in range(trials):
        k = rng.randrange(1, len(base))
        forged = coc.Ledger(led.dosar, h0, tsa)
        forged.entries = copy.deepcopy(base[:k])
        forged.append(ops["expert"], "operațiune inserată retroactiv", "x", h0, "x")
        name_to_op = {f"{o.nume} ({o.calitate})": o for o in ops.values()}
        for e in base[k:]:
            r = e["r"]
            forged.append(name_to_op[r["operator"]], r["operatiune"], r["instrument"],
                          bytes.fromhex(r["hash_date"]), r["act"])
        es = forged.entries
        det_internal += check(es)
        det_anchor += check(es) or es[-1]["h"] != anchored_head
    record("T7a", "rescriere cu toate cheile + mărci temporale noi — doar verificare internă",
           det_internal, trials, "limita modelului fără ancorare externă")
    record("T7b", "rescriere cu toate cheile + mărci temporale noi — cu ancorare la terț",
           det_anchor, trials)

    # T8: semnătură falsificată cu o cheie care nu figurează în registrul public de chei
    det = 0
    for _ in range(trials):
        es = copy.deepcopy(base)
        e = rng.choice(es)
        e["semnatura"] = coc.Ed25519PrivateKey.generate().sign(bytes.fromhex(e["h"])).hex()
        det += check(es)
    record("T8", "semnătură înlocuită cu una produsă de o cheie neautorizată", det, trials)

    # T9: modificarea momentului din marca temporală
    det = 0
    for _ in range(trials):
        es = copy.deepcopy(base)
        rng.choice(es)["marca_timp"]["t"] -= rng.randint(1, 10_000)
        det += check(es)
    record("T9", "antedatarea unei mărci temporale", det, trials)

    os.remove(img)
    return rows


# ------------------------------------------------------ (b) cost suplimentar
def exp_overhead(workdir: str, rng: random.Random, sizes_mib: list[int]) -> list[dict]:
    rows = []
    for mib in sizes_mib:
        src = os.path.join(workdir, f"src_{mib}.img")
        dst = os.path.join(workdir, f"dst_{mib}.img")
        extents = make_evidence(src, mib * 2**20, 256 * 1024, rng)
        acquire_baseline(src, dst)  # încălzire (cache)
        tb, tm, tl = [], [], []
        for rep in range(REPS_IO):
            # ordine alternată (A-B / B-A) pentru a nu favoriza sistematic o variantă
            if rep % 2:
                t = time.perf_counter(); h0, fh = acquire_model(src, dst, extents); t1 = time.perf_counter()
                tb_after = True
            else:
                tb_after = False
                t = time.perf_counter(); acquire_baseline(src, dst); tb.append(time.perf_counter() - t)
                t = time.perf_counter(); h0, fh = acquire_model(src, dst, extents); t1 = time.perf_counter()
            root = coc.merkle_root(fh)
            ops = make_operators(); tsa = coc.TimestampAuthority()
            led = coc.Ledger("dosar 123/P/2026", h0, tsa)
            typical_chain(led, ops, root, h0)
            t2 = time.perf_counter()
            tm.append(t2 - t)
            tl.append(t2 - t1)
            if tb_after:
                t = time.perf_counter(); acquire_baseline(src, dst); tb.append(time.perf_counter() - t)
        # corectitudine: hash-urile per fișier calculate în flux = cele calculate direct
        with open(src, "rb") as f:
            for s, ln in rng.sample(extents, min(50, len(extents))):
                f.seek(s)
                assert coc.sha256(f.read(ln)) == fh[extents.index((s, ln))]
        b, m = median_iqr(tb), median_iqr(tm)
        rows.append({
            "dimensiune_MiB": mib,
            "fisiere": len(extents),
            "baza_s_median": round(b["median"], 3),
            "model_s_median": round(m["median"], 3),
            "cost_suplimentar_s": round(m["median"] - b["median"], 3),
            "cost_suplimentar_pct": round(100 * (m["median"] - b["median"]) / b["median"], 1),
            "merkle_si_registru_s_median": round(median_iqr(tl)["median"], 4),
            "baza_IQR_s": [round(b["q1"], 3), round(b["q3"], 3)],
            "model_IQR_s": [round(m["q1"], 3), round(m["q3"], 3)],
            "debit_baza_MiB_s": round(mib / b["median"], 1),
        })
        os.remove(src); os.remove(dst)
    return rows


def exp_overhead_cpu(rng: random.Random, sizes_mib: list[int]) -> list[dict]:
    """Costul de CALCUL al modelului, fără disc: datele sunt deja în memorie.
    Baza = SHA-256 al imaginii; model = același hash + hash per fișier (aceeași trecere)
    + arbore Merkle + 6 înregistrări semnate."""
    rows = []
    for mib in sizes_mib:
        data = rng.randbytes(mib * 2**20)
        mv = memoryview(data)
        extents, off = [], 0
        while True:
            ln = max(1, int(rng.expovariate(1 / (256 * 1024))))
            gap = rng.randint(0, 4096)
            if off + gap + ln > len(data):
                break
            extents.append((off + gap, ln)); off += gap + ln
        tb, tm = [], []
        for rep in range(REPS_CPU + 1):  # prima rulare = încălzire, ignorată
            t = time.perf_counter(); h0 = hashlib.sha256(mv).digest(); b = time.perf_counter() - t
            t = time.perf_counter()
            h0 = hashlib.sha256(mv).digest()
            fh = [hashlib.sha256(mv[s:s + ln]).digest() for s, ln in extents]
            root = coc.merkle_root(fh)
            ops = make_operators(); tsa = coc.TimestampAuthority()
            led = coc.Ledger("dosar 123/P/2026", h0, tsa)
            typical_chain(led, ops, root, h0)
            m = time.perf_counter() - t
            if rep:
                tb.append(b); tm.append(m)
        bm, mm = median_iqr(tb), median_iqr(tm)
        rows.append({
            "dimensiune_MiB": mib,
            "fisiere": len(extents),
            "baza_s_median": round(bm["median"], 3),
            "model_s_median": round(mm["median"], 3),
            "cost_suplimentar_s": round(mm["median"] - bm["median"], 3),
            "cost_suplimentar_s_per_GiB": round((mm["median"] - bm["median"]) / (mib / 1024), 3),
            "raport_model_baza": round(mm["median"] / bm["median"], 2),
            "baza_IQR_s": [round(bm["q1"], 3), round(bm["q3"], 3)],
            "model_IQR_s": [round(mm["q1"], 3), round(mm["q3"], 3)],
        })
        del data, mv
    return rows


# ------------------------------------------------------ (c) timp de verificare
def exp_verify(lengths: list[int]) -> list[dict]:
    rows = []
    h0 = os.urandom(32)
    for n in lengths:
        ops = make_operators(); tsa = coc.TimestampAuthority()
        led = coc.Ledger("dosar 123/P/2026", h0, tsa)
        names = list(ops)
        t = time.perf_counter()
        for i in range(n):
            led.append(ops[names[i % 3]], f"operațiune {i}", "proto 1.0", h0, "act")
        t_build = time.perf_counter() - t
        keys = pubkeys(ops)
        ts = []
        for _ in range(REPS):
            t = time.perf_counter()
            v = coc.verify_ledger(led.entries, h0, led.dosar, keys, tsa.pub)
            ts.append(time.perf_counter() - t)
            assert v.ok
        m = median_iqr(ts)
        size = len(json.dumps(led.entries).encode())
        rows.append({
            "inregistrari": n,
            "verificare_ms_median": round(1000 * m["median"], 2),
            "verificare_ms_IQR": [round(1000 * m["q1"], 2), round(1000 * m["q3"], 2)],
            "us_per_inregistrare": round(1e6 * m["median"] / n, 1),
            "creare_ms_total": round(1000 * t_build, 1),
            "dimensiune_registru_KiB": round(size / 1024, 1),
        })
    return rows


# ----------------------------------------------------------- (d) dovezi Merkle
def exp_merkle(ns: list[int], rng: random.Random, probes: int = 1000) -> list[dict]:
    rows = []
    for n in ns:
        leaves = [rng.randbytes(32) for _ in range(n)]
        t = time.perf_counter(); levels = coc.merkle_levels(leaves); t_build = time.perf_counter() - t
        root = levels[-1][0]
        idx = [rng.randrange(n) for _ in range(probes)]
        lens, tg, tv = [], 0.0, 0.0
        for i in idx:
            t = time.perf_counter(); p = coc.merkle_proof(levels, i); tg += time.perf_counter() - t
            t = time.perf_counter(); ok = coc.merkle_verify(leaves[i], p, root); tv += time.perf_counter() - t
            assert ok
            lens.append(len(p))
        rows.append({
            "fisiere": n,
            "hash_uri_in_dovada_max": max(lens),
            "dimensiune_dovada_octeti_max": max(lens) * 32,
            "constructie_arbore_s": round(t_build, 3),
            "generare_dovada_us_medie": round(1e6 * tg / probes, 1),
            "verificare_dovada_us_medie": round(1e6 * tv / probes, 1),
        })
    return rows


# ------------------------------------------------------------------- main
def environment() -> dict:
    cpu = "necunoscut"
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next(l.split(":", 1)[1].strip() for l in f if l.startswith("model name"))
    except Exception:
        pass
    return {
        "python": sys.version.split()[0],
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "cpu": cpu,
        "nuclee": os.cpu_count(),
        "seed": SEED,
        "repetari": REPS,
    }


def write_csv(path: str, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results")
    ap.add_argument("--work", default="work")
    ap.add_argument("--sizes", default="256,1024,4096", help="dimensiuni imagine, MiB")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", default="a,b,b2,c,d", help="experimentele de rulat")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True); os.makedirs(a.work, exist_ok=True)
    only = set(a.only.split(","))
    sizes = [64] if a.quick else [int(s) for s in a.sizes.split(",")]

    path = os.path.join(a.out, "rezultate.json")
    res = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    res["mediu"] = environment()
    # fiecare experiment are propriul generator, deci rezultatele nu depind de ordinea rulării
    if "a" in only:
        print("(a) detectare alterări …", flush=True)
        res["a_detectare"] = exp_tamper(a.work, random.Random(SEED + 1), 100 if a.quick else 1000)
    if "b" in only:
        print("(b) cost suplimentar, cu disc …", flush=True)
        res["b_cost"] = exp_overhead(a.work, random.Random(SEED + 2), sizes)
    if "b2" in only:
        print("(b2) cost suplimentar, doar calcul …", flush=True)
        res["b2_cost_calcul"] = exp_overhead_cpu(random.Random(SEED + 3), [s for s in sizes if s <= 1024])
    if "c" in only:
        print("(c) verificare registru …", flush=True)
        res["c_verificare"] = exp_verify([10, 100] if a.quick else [10, 100, 1000, 10_000])
    if "d" in only:
        print("(d) dovezi Merkle …", flush=True)
        res["d_merkle"] = exp_merkle([100, 1000] if a.quick else [100, 1_000, 10_000, 100_000, 1_000_000],
                                     random.Random(SEED + 4))

    with open(path, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    for k in ("a_detectare", "b_cost", "b2_cost_calcul", "c_verificare", "d_merkle"):
        if k in res:
            write_csv(os.path.join(a.out, f"{k}.csv"), res[k])
    shutil.rmtree(a.work, ignore_errors=True)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
