#!/usr/bin/env python3
# =============================================================================
#  escalation — ce que l'agent ne corrige pas, il le documente (phase F).
# -----------------------------------------------------------------------------
#  E1 refuse les bumps majeurs. E3 refuse readOnlyRootFilesystem, runAsNonRoot
#  sans preuve, et capabilities sur un conteneur qui écoute sous 1024. E2 ferme
#  la porte après MAX_TENTATIVES rescans non concluants. Dans les quatre cas le
#  module a fait tout le travail d'analyse — et le résultat tenait dans une
#  ligne de log. L'inventaire de la phase F l'a chiffré : sur vingt et une
#  violations, onze partaient « en issue » vers une issue qui n'existait pas.
#
#  Ce module ne corrige rien et n'écrit rien dans le dépôt. Il ouvre une issue,
#  c'est-à-dire une phrase adressée à un humain : voilà ce que j'ai compris,
#  voilà pourquoi je ne le fais pas moi-même, voilà ce qu'il faudrait décider.
#
#  DÉCISIONS ENCAPSULÉES ICI :
#
#  1. UNE ISSUE PAR PROBLÈME, JAMAIS PAR PROPOSITION. Le registre E2 sépare le
#     problème (`finding_key`) de ce qu'on a suggéré (`proposal_key`) : le refus
#     humain porte sur la proposition, et on a le droit d'en refaire une autre.
#     Une issue, elle, dit « ceci demande un jugement » — et ça ne change pas
#     parce qu'on a reformulé le titre. La clé de dédup est donc le
#     `finding_key`, seul. Reformuler ne rouvre rien.
#
#  2. LA DÉDUP NE PASSE PAS PAR /search/issues. L'API de recherche GitHub est
#     ÉVENTUELLEMENT COHÉRENTE : une issue créée il y a dix secondes n'y figure
#     pas encore. La dédup rouvrirait donc la même issue à chaque cycle de scan
#     rapproché — exactement le défaut que ce module existe pour éviter. On
#     liste les issues portant le label de l'agent et on cherche un marqueur
#     dans leur corps : une requête, déterministe, immédiatement cohérente.
#
#  3. UNE ISSUE FERMÉE PAR UN HUMAIN NE SE ROUVRE JAMAIS. C'est le pendant
#     exact du refus de PR en E2 : fermer, c'est répondre. Rouvrir serait
#     reposer la question à quelqu'un qui vient d'y répondre.
#
#  4. DANS LE DOUTE, ON NE CRÉE PAS. Si GitHub ne rend pas la liste, on ignore
#     ce qui existe déjà : créer à l'aveugle produirait le doublon. Le doute
#     profite au silence, jamais au bruit — la règle de `statut-pr-inconnu`
#     en E2, appliquée ici.
#
#  5. UN PLAFOND, COMME POUR LES PRs. Vingt issues que personne ne lit valent
#     zéro issue. Le plafond est plus haut que celui des PRs (5) parce qu'une
#     issue ne demande pas de revue de code — mais il existe.
#
#  6. LES PULL REQUESTS SONT DES ISSUES. `GET /repos/{repo}/issues` rend AUSSI
#     les PRs : c'est une particularité de l'API GitHub, pas un bug. Une PR de
#     l'agent portant le label ferait monter le plafond pour rien, et pire, une
#     PR portant le marqueur serait prise pour l'issue du problème. On les
#     écarte sur la présence de la clé `pull_request`.
#
#  7. AUCUNE ALLOW-LIST DE FICHIERS. Une issue n'écrit ni dans le dépôt ni dans
#     le cluster. Le contrôle qui compte ailleurs — l'agent ne touche pas à ses
#     propres garde-fous — n'a pas d'objet ici. Le seul risque est le bruit,
#     et c'est la décision n° 5 qui le traite.
#
#  8. LE RÉSEAU EST INJECTÉ, LE REGISTRE AUSSI. `gh` est passé par l'appelant,
#     comme `statut_pr` en E2 et comme la séparation collect/evaluate en D. Ce
#     module n'appelle pas `findings_ledger` : c'est `remediation.py` qui
#     enregistre, exactement comme il le fait déjà après l'ouverture d'une PR.
#     Une seule couche écrit l'état, et on peut tester celle-ci sans GitHub.
#
#  OÙ L'APPELER (phase F, patch-remediation-f.py) :
#    - `_build_hardening`  : sur `vue["issue"]`, les clés à arbitrer
#    - `_build_patch`      : sur le refus `image-major`
#    - la porte du registre : sur `trop-de-tentatives`
#  Destination : manifests/sre-agent/bridge/src/escalation.py
# =============================================================================
import os

# Le label est la clé de la liste : c'est lui qui borne la requête de dédup.
LABEL = os.environ.get("ESCALATION_LABEL", "ai-escalation")
MAX_ISSUES_OUVERTES = int(os.environ.get("MAX_ISSUES_OUVERTES", "20"))

# Le marqueur vit dans le CORPS, pas dans le titre : le titre est rédigé pour
# un humain et peut changer, le marqueur ne doit jamais changer (décision n° 1).
# Commentaire HTML : GitHub ne le rend pas, il ne pollue pas la lecture.
MARQUEUR_FMT = "<!-- sre-agent:finding:{fkey} -->"


def log(msg):
    print(f"[escalation] {msg}", flush=True)


def _ok(raison, detail, **extra):
    d = {"ok": True, "raison": raison, "detail": detail}
    d.update(extra)
    return d


def _ko(raison, detail, **extra):
    d = {"ok": False, "raison": raison, "detail": detail}
    d.update(extra)
    return d


# ------------------------------------------------------------------ marqueur
def marqueur(fkey):
    """L'empreinte du problème, telle qu'elle est écrite dans le corps."""
    return MARQUEUR_FMT.format(fkey=fkey)


# ------------------------------------------------------- lecture (PURE)
def vraies_issues(issues):
    """Écarte les pull requests rendues par /repos/{repo}/issues (n° 6)."""
    return [i for i in (issues or ()) if "pull_request" not in i]


def trouver(issues, fkey):
    """L'issue déjà ouverte OU déjà fermée pour ce problème, sinon None.

    Fonction PURE : elle reçoit la liste déjà collectée. C'est elle qu'on relit
    quand une issue se duplique, et elle se teste sans GitHub.
    """
    m = marqueur(fkey)
    for issue in vraies_issues(issues):
        if m in (issue.get("body") or ""):
            return issue
    return None


def ouvertes(issues):
    return [i for i in vraies_issues(issues)
            if (i.get("state") or "open") == "open"]


# ------------------------------------------------------- rédaction (PURE)
def titre(sujet, deployment=None, namespace=None):
    """Ce qu'on lit dans la liste des issues : le sujet, puis la cible."""
    cible = "/".join(x for x in (namespace, deployment) if x)
    return f"[sre-agent] {sujet}" + (f" — {cible}" if cible else "")


def corps(fkey, resume, raisons=None, contexte=None, source=""):
    """Le corps que lit l'humain.

    `raisons` : liste de (quoi, pourquoi) — le tableau que produisent déjà
    `hardening_rules.analyser()` dans `issue` et le refus de `check_image_change`.
    On ne reformule pas ces phrases : elles ont été écrites par la règle qui a
    refusé, c'est elle qui sait pourquoi.
    """
    lignes = ["## 🧭 Arbitrage demandé", "", resume or "", ""]
    if raisons:
        lignes += ["| Point | Pourquoi l'agent ne le fait pas |",
                   "|---|---|"]
        for quoi, pourquoi in raisons:
            lignes.append(f"| `{quoi}` | {pourquoi} |")
        lignes.append("")
    if contexte:
        lignes += ["### Contexte mesuré", ""]
        for cle, valeur in contexte:
            lignes.append(f"- **{cle}** : {valeur}")
        lignes.append("")
    lignes += [
        "---",
        "",
        "Cette issue a été ouverte automatiquement parce que la correction "
        "sort du périmètre que l'agent s'autorise. Elle ne sera **pas** "
        "rouverte si vous la fermez : la fermer, c'est répondre.",
        "",
    ]
    if source:
        lignes += [f"_Source du verdict : {source}._", ""]
    # Le marqueur en dernier : invisible au rendu, stable dans le temps.
    lignes.append(marqueur(fkey))
    return "\n".join(lignes)


# --------------------------------------------------------------- lecture I/O
def lister(repo, gh):
    """Les issues de l'agent, ouvertes ET fermées (décision n° 3).

    `gh(method, path, body=None)` est injecté par l'appelant — dans le bridge
    c'est `_gh` de remediation.py, avec son token déjà lié.
    """
    return gh("GET", f"/repos/{repo}/issues"
                     f"?state=all&labels={LABEL}&per_page=100")


# ------------------------------------------------------------- point d'entrée
def ouvrir(fkey, sujet, resume, raisons=None, contexte=None, source="",
           repo=None, gh=None, issues=None, deployment=None, namespace=None,
           labels=()):
    """Ouvre l'issue, ou dit pourquoi elle ne s'ouvre pas.

    Rend {ok: True, url, number} après création, {ok: False, raison, detail}
    sinon — avec `url` renseignée quand l'issue existe déjà, pour que
    l'appelant puisse pointer dessus au lieu d'en ouvrir une autre.

    Ne lève jamais : une escalade qui plante empêcherait la remédiation qui
    l'entoure de se terminer.
    """
    if not fkey:
        return _ko("fkey-absente",
                   "sans clé de problème, la dédup est impossible : on "
                   "n'ouvre pas une issue qu'on ne saura pas reconnaître")
    if gh is None or not repo:
        return _ko("desactive",
                   "aucun client GitHub fourni : l'escalade reste une ligne "
                   "de log, comme avant la phase F")

    if issues is None:
        try:
            issues = lister(repo, gh)
        except Exception as e:
            # Décision n° 4 : sans la liste, on ignore ce qui existe déjà.
            return _ko("liste-indisponible",
                       f"impossible de lister les issues ({e}) : on ne crée "
                       f"pas à l'aveugle, ce serait le doublon assuré")

    existante = trouver(issues, fkey)
    if existante is not None:
        etat = existante.get("state") or "open"
        url = existante.get("html_url", "")
        numero = existante.get("number")
        if etat == "open":
            return _ko("deja-ouverte",
                       f"issue #{numero} déjà ouverte pour ce problème",
                       url=url, number=numero)
        return _ko("fermee-par-humain",
                   f"issue #{numero} fermée par un humain : fermer, c'est "
                   f"répondre — on ne repose pas la question",
                   url=url, number=numero)

    n = len(ouvertes(issues))
    if n >= MAX_ISSUES_OUVERTES:
        return _ko("plafond-issues",
                   f"{n} issues de l'agent déjà ouvertes (plafond "
                   f"{MAX_ISSUES_OUVERTES}) : au-delà, on ne documente plus, "
                   f"on encombre")

    charge = {
        "title": titre(sujet, deployment, namespace),
        "body": corps(fkey, resume, raisons, contexte, source),
        "labels": sorted({LABEL, *(x for x in labels if x)}),
    }
    try:
        issue = gh("POST", f"/repos/{repo}/issues", charge)
    except Exception as e:
        return _ko("creation-echouee",
                   f"GitHub a refusé la création ({e}) : le diagnostic reste "
                   f"dans Slack, rien n'est perdu de définitif")

    numero = issue.get("number")
    url = issue.get("html_url", "")
    log(f"issue #{numero} ouverte pour {fkey} — {charge['title']}")
    return _ok("creee", f"issue #{numero} ouverte", url=url, number=numero,
               titre=charge["title"])


def resume_module():
    """Une ligne pour les logs et le rapport."""
    return (f"label « {LABEL} », plafond {MAX_ISSUES_OUVERTES} issues "
            f"ouvertes, dédup par marqueur de finding")

