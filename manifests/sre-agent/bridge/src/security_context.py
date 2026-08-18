#!/usr/bin/env python3
# =============================================================================
#  security_context — le toolset sécurité de l'agent (phase D).
# -----------------------------------------------------------------------------
#  Pourquoi : depuis la phase C, l'agent REÇOIT les violations StackRox. Il ne
#  sait pas encore lesquelles comptent. « CRITICAL » ne veut rien dire seul :
#  la moitié des critical ne sont pas exploitables, et un medium activement
#  exploité est plus urgent que dix critical théoriques. Ce module apporte les
#  trois informations qui manquent pour trancher :
#
#    EPSS        — probabilité d'exploitation dans les 30 jours (FIRST.org)
#    CISA KEV    — la CVE est-elle exploitée EN RÉEL, aujourd'hui
#    API Central — cette image tourne-t-elle encore ? où ? exposée ?
#
#  Règles d'architecture (identiques au bridge, à l'adapter, au gateway) :
#  stdlib uniquement, pas de dépendance, pas de LLM. Le tri doit rester
#  explicable ligne à ligne — c'est ce qui permet de le défendre en war room
#  et de le tester.
#
#  DÉCISIONS ENCAPSULÉES ICI :
#
#  1. SÉPARATION I/O / DÉCISION. `evaluate()` est PURE : elle reçoit des
#     données déjà collectées et rend un verdict. Tout le réseau est dans
#     `collect()`. C'est ce qui rend le triage testable sans Internet et sans
#     cluster — la leçon de `build_alerts()` en phase C, appliquée d'emblée.
#
#  2. DÉGRADATION, JAMAIS D'EXCEPTION. Si EPSS, KEV ou Central sont
#     injoignables, le verdict sort quand même, avec la liste des sources
#     manquantes dans `degraded`. Un agent qui se tait parce qu'une API tierce
#     est en panne est pire qu'un agent approximatif : le pipeline de sécurité
#     ne doit pas dépendre de la disponibilité d'Internet.
#
#  3. LE CONTEXTE D'EXÉCUTION PEUT DÉCLASSER, JAMAIS SURCLASSER. Une CVE sur
#     une image qui ne tourne plus devient `vex` (à documenter, pas à corriger
#     en urgence). Mais une image non exposée ne remonte jamais au-dessus de
#     ce que KEV/EPSS justifient : on ne s'autorise pas à paniquer sur du
#     contexte, seulement à se calmer.
#
#  4. SEUL KEV AUTORISE `immediate`. C'est le seul signal qui dit « exploité,
#     pour de vrai, maintenant ». C'est donc le seul qui ouvre le droit
#     d'escalader vers l'astreinte — la porte laissée fermée en phase C
#     (`continue: false`) n'a de sens que si son ouverture est rare et motivée.
#
#  5. CACHE DISQUE À TTL. Le catalogue KEV pèse ~2 Mo et ne bouge qu'une fois
#     par jour ; EPSS se recalcule quotidiennement. Sur le lien lent de la VM
#     (leçon du §3), retélécharger à chaque alerte serait absurde.
# =============================================================================
import json
import os
import re
import ssl
import time
import urllib.parse
import urllib.request

EPSS_URL = os.environ.get("EPSS_URL", "https://api.first.org/data/v1/epss")
KEV_URL = os.environ.get(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json")
# Central : même service que celui qui refuse les images à l'admission.
CENTRAL_API = os.environ.get(
    "CENTRAL_API", "https://central.stackrox.svc.cluster.local:443")
# Jeton API Central, rôle Analyst (lecture seule). Secret monté par env,
# JAMAIS dans Git — même règle que holmes-slack-webhook et consorts.
ROX_API_TOKEN = os.environ.get("ROX_API_TOKEN", "")

CACHE_DIR = os.environ.get("SEC_CACHE_DIR", "/tmp/security-context")
KEV_TTL_S = int(os.environ.get("KEV_TTL_S", str(24 * 3600)))
EPSS_TTL_S = int(os.environ.get("EPSS_TTL_S", str(6 * 3600)))
HTTP_TIMEOUT_S = int(os.environ.get("HTTP_TIMEOUT_S", "10"))

# Seuils EPSS. Le percentile est plus parlant que la probabilité brute pour un
# humain ("dans le top 1 % des CVE les plus susceptibles d'être exploitées"),
# mais c'est la probabilité qui décide : elle est comparable dans le temps.
EPSS_HAUTE = float(os.environ.get("EPSS_HAUTE", "0.10"))
EPSS_MOYENNE = float(os.environ.get("EPSS_MOYENNE", "0.01"))

PRIORITES = ("immediate", "haute", "moyenne", "basse", "vex")


def log(msg):
    print(f"[security-context] {msg}", flush=True)


# Les policies de vulnerabilite nomment les CVE dans le TEXTE des messages de
# violation ("... contains CVE-2024-1234") : aucun champ structure ne les
# porte. L extraction vit ICI et non dans le bridge, pour etre testee.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(*textes):
    """Releve les CVE citees dans un ou plusieurs textes.

    Deduplique, normalise en majuscules, trie. Renvoie [] plutot que None :
    l appelant enchaine sur collect() sans test prealable, et une violation
    sans CVE (signature, configuration) reste traitee pour son contexte
    d execution.
    """
    trouve = set()
    for texte in textes:
        if texte:
            trouve.update(m.upper() for m in CVE_RE.findall(str(texte)))
    return sorted(trouve)


# --------------------------------------------------------------- cache disque
def _cache_path(name):
    return os.path.join(CACHE_DIR, name + ".json")


def _cache_read(name, ttl):
    """Renvoie la valeur en cache si elle est encore fraîche, sinon None."""
    try:
        path = _cache_path(name)
        if time.time() - os.path.getmtime(path) > ttl:
            return None
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _cache_write(name, value):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = _cache_path(name) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(value, f)
        os.replace(tmp, _cache_path(name))
    except Exception as e:                      # un cache qui échoue ne doit
        log(f"cache non écrit ({name}) : {e}")  # jamais casser la collecte


# ---------------------------------------------------------------------- HTTP
def _get(url, headers=None, insecure=False):
    req = urllib.request.Request(url, headers=headers or {})
    ctx = None
    if insecure:
        # Central présente un certificat interne signé par sa propre CA. On
        # est dans le cluster, sur un Service ClusterIP : le risque est le
        # même que celui déjà assumé pour /webhook en phase C. Le durcissement
        # (monter la CA de Central) est un candidat phase G.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=ctx) as r:
        return json.loads(r.read())


# ------------------------------------------------------------------ collecte
def fetch_kev():
    """Ensemble des CVE du catalogue CISA KEV. {} en cas d'échec."""
    cached = _cache_read("kev", KEV_TTL_S)
    if cached is not None:
        return cached
    data = _get(KEV_URL)
    kev = {}
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").upper()
        if cve:
            kev[cve] = {
                "added": v.get("dateAdded"),
                "due": v.get("dueDate"),
                # Le champ ransomware distingue « exploité » de « exploité par
                # des rançongiciels » : la seconde catégorie change la posture.
                "ransomware": (v.get("knownRansomwareCampaignUse")
                               or "").lower() == "known"}
    _cache_write("kev", kev)
    log(f"KEV rafraîchi : {len(kev)} CVE exploitées connues")
    return kev


def fetch_epss(cves):
    """{CVE: {epss, percentile}} pour les CVE demandées. {} en cas d'échec."""
    cves = [c.upper() for c in cves if c]
    if not cves:
        return {}
    cached = _cache_read("epss", EPSS_TTL_S) or {}
    manquantes = [c for c in cves if c not in cached]
    if manquantes:
        # L'API accepte une liste ; on borne à 100 par requête (limite doc).
        for i in range(0, len(manquantes), 100):
            lot = manquantes[i:i + 100]
            url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(lot)})}"
            for row in _get(url).get("data", []):
                cached[(row.get("cve") or "").upper()] = {
                    "epss": float(row.get("epss", 0.0)),
                    "percentile": float(row.get("percentile", 0.0))}
            # Une CVE absente de la réponse est une CVE qu'EPSS ne score pas
            # (trop récente). On mémorise l'absence pour ne pas la redemander.
            for c in lot:
                cached.setdefault(c, None)
        _cache_write("epss", cached)
    return {c: cached.get(c) for c in cves if cached.get(c)}


def fetch_runtime(image=None, deployment=None, namespace=None):
    """Contexte d'exécution vu par Central : la charge tourne-t-elle encore,
    et est-elle jointe depuis l'extérieur ? {} si Central est injoignable ou
    si aucun jeton n'est configuré."""
    if not ROX_API_TOKEN:
        raise RuntimeError("ROX_API_TOKEN absent")
    clauses = []
    if deployment:
        clauses.append(f'Deployment:{deployment}')
    if namespace:
        clauses.append(f'Namespace:{namespace}')
    if image and not clauses:
        clauses.append(f'Image:{image}')
    query = urllib.parse.urlencode({"query": "+".join(clauses)}) if clauses \
        else ""
    data = _get(f"{CENTRAL_API}/v1/deployments?{query}",
                headers={"Authorization": f"Bearer {ROX_API_TOKEN}"},
                insecure=True)
    deps = data.get("deployments", [])
    return {
        "running": bool(deps),
        "deployments": [d.get("name") for d in deps][:10],
        "exposed": _any_exposed(deps)}


# Exposition hors du cluster. `HOST` est volontairement exclu : un hostPort
# n'est pas une publication au meme titre qu'un NodePort ou une Route.
EXPOSITIONS_EXTERNES = ("EXTERNAL", "NODE", "ROUTE")
MAX_DETAILS = 5


def _any_exposed(deps):
    """Une des charges est-elle joignable depuis l'exterieur du cluster ?

    Corrige le 18/08 (dette §7.6). /v1/deployments renvoie des objets
    ListDeployment a huit champs (id, hash, name, cluster, clusterId,
    namespace, created, priority) : NI PORTS NI EXPOSITION. Le champ lu
    auparavant n'existait simplement pas, et `exposed` valait toujours False.
    Le detail vit dans /v1/deployments/{id}.

    Borne a MAX_DETAILS fiches : une requete filtree en renvoie rarement plus,
    et on ne deroule pas 69 fiches sur un lien lent. Un echec de detail ne leve
    pas : on reste conservateur (pas de preuve d'exposition => pas d'escalade),
    conformement a la decision n° 3 du module.
    """
    for d in deps[:MAX_DETAILS]:
        pid = d.get("id")
        if not pid:
            continue
        try:
            detail = _get(f"{CENTRAL_API}/v1/deployments/{pid}",
                          headers={"Authorization": f"Bearer {ROX_API_TOKEN}"},
                          insecure=True)
        except Exception as e:
            log(f"detail deploiement indisponible ({pid}) : {e}")
            continue
        for port in detail.get("ports") or []:
            if (port.get("exposure") or "").upper() in EXPOSITIONS_EXTERNES:
                return True
    return False


# ------------------------------------------------------------------- verdict
def evaluate(cve, epss=None, kev=None, runtime=None):
    """CVE + contexte -> verdict motivé. Fonction PURE : aucun I/O.

    C'est elle que les tests couvrent, et c'est elle qu'on relit quand un
    verdict surprend. Toute la logique de priorisation tient ici.
    """
    cve = (cve or "").upper()
    epss = epss or {}
    kev = kev or {}
    runtime = runtime or {}

    proba = epss.get("epss")
    percentile = epss.get("percentile")
    exploitee = bool(kev)
    tourne = runtime.get("running")
    exposee = bool(runtime.get("exposed"))

    # 1. Le socle : ce que l'exploitabilité justifie, sans contexte.
    if exploitee:
        priorite = "immediate"
        pourquoi = ["inscrite au catalogue CISA KEV : exploitée en réel"]
        if kev.get("ransomware"):
            pourquoi.append("utilisée par des campagnes de rançongiciel")
        if kev.get("due"):
            pourquoi.append(f"échéance CISA {kev['due']}")
    elif proba is None:
        priorite = "moyenne"
        pourquoi = ["aucun score EPSS (CVE trop récente ou non scorée) : "
                    "traitée par défaut au milieu de la file"]
    elif proba >= EPSS_HAUTE:
        priorite = "haute"
        pourquoi = [f"EPSS {proba:.3f} — exploitation probable à 30 jours"]
    elif proba >= EPSS_MOYENNE:
        priorite = "moyenne"
        pourquoi = [f"EPSS {proba:.3f} — exploitation plausible"]
    else:
        priorite = "basse"
        pourquoi = [f"EPSS {proba:.3f} — exploitation très improbable"]
    if percentile is not None and not exploitee:
        pourquoi.append(f"percentile {percentile:.2%} des CVE")

    # 2. Le contexte ne peut que DÉCLASSER (décision n° 3).
    if tourne is False:
        priorite = "vex"
        pourquoi.append("aucune charge ne fait tourner cette image dans le "
                        "cluster : à documenter en VEX, pas à corriger en "
                        "urgence")
    elif tourne and not exposee and priorite == "immediate":
        # Exploitée, mais pas joignable de l'extérieur : on reste haut sans
        # aller jusqu'au réveil. La nuance qui évite les fausses urgences.
        priorite = "haute"
        pourquoi.append("charge non exposée hors du cluster : traitée en "
                        "priorité haute plutôt qu'en escalade immédiate")
    elif exposee:
        pourquoi.append("charge exposée hors du cluster")

    return {
        "cve": cve,
        "epss": proba,
        "epss_percentile": percentile,
        "kev": exploitee,
        "kev_ransomware": bool(kev.get("ransomware")),
        "running": tourne,
        "exposed": exposee if tourne else False,
        "priorite": priorite,
        "escalade": priorite == "immediate",
        "justification": " ; ".join(pourquoi),
    }


def collect(cves, image=None, deployment=None, namespace=None):
    """Le point d'entrée du bridge : CVE + charge -> verdicts triés.

    Ne lève JAMAIS (décision n° 2) : chaque source indisponible est nommée
    dans `degraded`, et le verdict est rendu avec ce qui reste.
    """
    degraded = []
    kev = {}
    epss = {}
    runtime = {}
    try:
        kev = fetch_kev()
    except Exception as e:
        degraded.append("kev")
        log(f"KEV indisponible : {e}")
    try:
        epss = fetch_epss(cves)
    except Exception as e:
        degraded.append("epss")
        log(f"EPSS indisponible : {e}")
    try:
        runtime = fetch_runtime(image, deployment, namespace)
    except Exception as e:
        degraded.append("central")
        log(f"contexte Central indisponible : {e}")

    verdicts = [evaluate(c, epss.get((c or "").upper()),
                         kev.get((c or "").upper()), runtime)
                for c in cves if c]
    verdicts.sort(key=lambda v: PRIORITES.index(v["priorite"]))
    return {
        "verdicts": verdicts,
        "degraded": degraded,
        "escalade": any(v["escalade"] for v in verdicts),
        "resume": resume(verdicts, degraded),
    }


def resume(verdicts, degraded=None):
    """Une phrase pour la war room — c'est ce que l'humain lit en premier."""
    if not verdicts:
        return "aucune CVE à trier."
    compte = {}
    for v in verdicts:
        compte[v["priorite"]] = compte.get(v["priorite"], 0) + 1
    parts = [f"{compte[p]} {p}" for p in PRIORITES if p in compte]
    texte = f"{len(verdicts)} CVE triées : " + ", ".join(parts) + "."
    kevs = [v["cve"] for v in verdicts if v["kev"]]
    if kevs:
        texte += (f" Exploitées en réel (KEV) : {', '.join(kevs[:5])}"
                  f"{' …' if len(kevs) > 5 else ''}.")
    if degraded:
        texte += (f" ⚠️ tri dégradé, sources indisponibles : "
                  f"{', '.join(degraded)}.")
    return texte


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if a.upper().startswith("CVE-")]
    print(json.dumps(collect(args), indent=2, ensure_ascii=False))

