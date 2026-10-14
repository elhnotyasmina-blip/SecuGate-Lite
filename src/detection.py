from src.contrat import Signal, Verdict
def est_deja_vu(sig: Signal, vus: set) -> bool:
 raise NotImplementedError
def compter_echecs(sig: Signal, compteur: dict) -> int:
 raise NotImplementedError
def chercher_procedures(sig: Signal, base: dict) -> list:
 raise NotImplementedError
def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
 raise NotImplementedError
def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
 raise NotImplementedError