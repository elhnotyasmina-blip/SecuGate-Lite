import re

from src.contrat import Signal

_PARAM_SENSIBLE = re.compile(r"\b(token|password|session|key)=([^&\s]*)", re.IGNORECASE)

_GRAVITE_SCAN = {
    "blocker": "CRITIQUE",
    "critical": "ELEVEE",
    "major": "MOYENNE",
    "minor": "FAIBLE",
}


def masquer_ip(ip: str) -> str:
    parties = ip.split(".")
    if len(parties) != 4:
        raise ValueError(f"Adresse IP invalide : {ip!r}")
    parties[-1] = "x"
    return ".".join(parties)


def masquer_parametres(chemin: str) -> str:
    return _PARAM_SENSIBLE.sub(r"\1=[MASQUE]", chemin)


def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    champs = ligne.split()
    if len(champs) < 6:
        raise ValueError(f"Ligne invalide (6 champs attendus) : {ligne!r}")
    date, heure, ip, methode, chemin, statut = champs[:6]
    code = int(statut)

    chemin_seul = chemin.split("?")[0]
    if chemin_seul == "/login" and code in (401, 403):
        type_ = "LOGIN_ECHEC"
    else:
        type_ = "ACCES"

    if code >= 500:
        gravite = "ELEVEE"
    elif code >= 400:
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"

    message = f"{methode} {masquer_parametres(chemin)} -> {statut} depuis {masquer_ip(ip)}"
    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="ACCES",
        ip=ip,
        cible=cible,
        type=type_,
        gravite=gravite,
        message=message,
    )


def normaliser_scan(rapport: dict, numero: int) -> Signal:
    for cle in ("rule", "component", "severity", "message", "date"):
        if cle not in rapport:
            raise ValueError(f"Cle manquante dans le rapport : {cle}")
    gravite = _GRAVITE_SCAN.get(str(rapport["severity"]).lower(), "FAIBLE")
    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=rapport["date"],
        source="SCAN",
        ip="",
        cible=rapport["component"],
        type="FAILLE",
        gravite=gravite,
        message=f"Faille {rapport['rule']} : {rapport['message']}",
    )