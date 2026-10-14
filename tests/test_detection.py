from src.detection import (analyser, chercher_procedures, compter_echecs,
                           est_deja_vu, evaluer)
def test_doublon_secondes_differentes(self):
        vus = set()
        a = sig("LOGIN_ECHEC", "MOYENNE")
        b = sig("LOGIN_ECHEC", "MOYENNE")
        b.timestamp = "2026-10-05T10:00:01Z"
        self.assertFalse(est_deja_vu(a, vus))
        self.assertFalse(est_deja_vu(b, vus))