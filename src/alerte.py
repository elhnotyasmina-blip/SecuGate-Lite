from src.contrat import Alerte, Signal, Verdict

_CANAUX = {
    "CRITIQUE": "TELEPHONE",
    "ELEVEE": "SLACK",
    "MOYENNE": "EMAIL",
    "FAIBLE": "TABLEAU",
}


def choisir_canal(niveau: str) -> str:
    if niveau not in _CANAUX:
        raise ValueError(f"Niveau inconnu : {niveau!r}")
    return _CANAUX[niveau]


def rediger(sig: Signal, verdict: Verdict) -> str:
    return "\n".join([
        f"[{verdict.niveau}] Cible : {sig.cible}",
        f"Signal : {sig.message}",
        f"Explication : {verdict.explication}",
        f"Action proposee : {verdict.action}",
        f"Sources : {', '.join(verdict.sources)}",
    ])


def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    al = Alerte(
        signal_id=sig.id,
        canal=choisir_canal(verdict.niveau),
        destinataire="equipe-secu",
        texte=rediger(sig, verdict),
    )
    journal.append(al)
    sig.statut = "ALERTE"
    return al


def valider_action(verdict: Verdict, reponse: str) -> bool:
    if not verdict.sensible:
        return True
    return reponse.strip().lower() in ("o", "oui", "ok", "yes")