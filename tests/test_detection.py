from src.detection import (analyser, chercher_procedures, compter_echecs,
                           est_deja_vu, evaluer)
def test_doublon_secondes_differentes(self):
        vus = set()
        a = sig("LOGIN_ECHEC", "MOYENNE")
        b = sig("LOGIN_ECHEC", "MOYENNE")
        b.timestamp = "2026-10-05T10:00:01Z"
        self.assertFalse(est_deja_vu(a, vus))
        self.assertFalse(est_deja_vu(b, vus))
def test_compter_echecs(self):
        c = {}
        e = sig("LOGIN_ECHEC", "MOYENNE")
        self.assertEqual(compter_echecs(e, c), 1)
        self.assertEqual(compter_echecs(e, c), 2)

def test_compter_hors_echec(self):
        c = {}
        self.assertEqual(compter_echecs(sig(), c), 0)
        self.assertEqual(c, {})
def test_chercher_procedures(self):
        s = sig(message="POST /login -> 401")
        self.assertEqual(chercher_procedures(s, PROCEDURES),
                         [PROCEDURES["login"]])
        self.assertEqual(chercher_procedures(sig(), PROCEDURES), [])
        