import unittest
from src.contrat import PROCEDURES, Signal
from src.detection import (analyser, chercher_procedures, compter_echecs,
                           est_deja_vu, evaluer)


def sig(type_="ACCES", gravite="FAIBLE", message="GET /home -> 200",
        ip="10.0.0.5"):
    return Signal("SIG-00001", "2026-10-05T10:00:00Z", "ACCES", ip, "web-app",
                  type_, gravite, message)


class TestDetection(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_deja_vu(sig(), vus))
        self.assertTrue(est_deja_vu(sig(), vus))

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

    def test_evaluer_echecs_login(self):
        e = sig("LOGIN_ECHEC", "MOYENNE")
        self.assertEqual(evaluer(e, 5), "CRITIQUE")
        self.assertEqual(evaluer(e, 4), "MOYENNE")

    def test_evaluer_gravite_signal(self):
        self.assertEqual(evaluer(sig("FAILLE", "ELEVEE")), "ELEVEE")

    def test_analyser_critique(self):
        e = sig("LOGIN_ECHEC", "MOYENNE", "POST /login -> 401")
        v = analyser(e, PROCEDURES, 5)
        self.assertEqual(v.niveau, "CRITIQUE")
        self.assertEqual(v.action, "Bloquer l'IP 10.0.0.5")
        self.assertTrue(v.sensible)
        self.assertEqual(e.statut, "ANALYSE")

    def test_analyser_inconnu(self):
        v = analyser(sig(), PROCEDURES)
        self.assertEqual(v.explication,
                         "Cause inconnue : analyse manuelle requise")
        self.assertEqual(v.action, "Surveiller")
        self.assertFalse(v.sensible)


if __name__ == "__main__":
    unittest.main()