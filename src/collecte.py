from src.contrat import Signal
def masquer_ip(ip: str) -> str:
    raise NotImplementedError
def masquer_parametres(chemin: str) -> str:
    raise NotImplementedError
def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    raise NotImplementedError
def normaliser_scan(rapport: dict, numero: int) -> Signal:
    raise NotImplementedError