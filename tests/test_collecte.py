import unittest

from src.collecte import (masquer_ip, masquer_parametres, normaliser_acces,
                          normaliser_scan)

LIGNE = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"
RAPPORT = {"rule": "S3649", "component": "backend", "severity": "blocker",
           "message": "injection SQL possible", "date": "2026-10-05T10:05:00Z"}


class TestMasquage(unittest.TestCase):
    def test_masquer_ip(self):
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")

    def test_masquer_ip_invalide(self):
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")
        with self.assertRaises(ValueError):
            masquer_ip("1.2.3.4.5")

    def test_masquer_parametres(self):
        self.assertEqual(masquer_parametres("/api?id=3&token=abc123"),
                         "/api?id=3&token=[MASQUE]")

    def test_masquer_parametres_casse_et_multiples(self):
        self.assertEqual(masquer_parametres("/a?Password=x1&KEY=k2&session=s3&id=7"),
                         "/a?Password=[MASQUE]&KEY=[MASQUE]&session=[MASQUE]&id=7")

    def test_masquer_parametres_rien_a_masquer(self):
        self.assertEqual(masquer_parametres("/home"), "/home")


class TestNormaliserAcces(unittest.TestCase):
    def test_login_echec(self):
        sig = normaliser_acces(LIGNE, 42)
        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.source, "ACCES")
        self.assertEqual(sig.ip, "192.168.1.15")
        self.assertEqual(sig.cible, "web-app")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")
        self.assertEqual(sig.message, "POST /login -> 401 depuis 192.168.1.x")
        self.assertEqual(sig.statut, "NOUVEAU")

    def test_login_403(self):
        sig = normaliser_acces("2026-10-05 10:00:00 1.2.3.4 POST /login 403", 1)
        self.assertEqual(sig.type, "LOGIN_ECHEC")

    def test_login_reussi_est_acces(self):
        sig = normaliser_acces("2026-10-05 10:00:00 1.2.3.4 POST /login 200", 1)
        self.assertEqual(sig.type, "ACCES")
        self.assertEqual(sig.gravite, "FAIBLE")

    def test_login_avec_parametres(self):
        sig = normaliser_acces("2026-10-05 10:00:00 1.2.3.4 POST /login?next=/a 401", 1)
        self.assertEqual(sig.type, "LOGIN_ECHEC")

    def test_gravites(self):
        base = "2026-10-05 10:00:00 1.2.3.4 GET /x {}"
        self.assertEqual(normaliser_acces(base.format(500), 1).gravite, "ELEVEE")
        self.assertEqual(normaliser_acces(base.format(404), 1).gravite, "MOYENNE")
        self.assertEqual(normaliser_acces(base.format(200), 1).gravite, "FAIBLE")

    def test_message_masque(self):
        sig = normaliser_acces(
            "2026-10-05 10:03:00 10.0.0.7 GET /api/users?id=3&token=abc123 200", 8)
        self.assertEqual(sig.message,
                         "GET /api/users?id=3&token=[MASQUE] -> 200 depuis 10.0.0.x")
        self.assertEqual(sig.type, "ACCES")

    def test_cible_personnalisee(self):
        sig = normaliser_acces(LIGNE, 1, cible="api")
        self.assertEqual(sig.cible, "api")

    def test_ligne_trop_courte(self):
        with self.assertRaises(ValueError):
            normaliser_acces("2026-10-05 10:00:00 1.2.3.4 GET", 1)


class TestNormaliserScan(unittest.TestCase):
    def test_scan(self):
        sig = normaliser_scan(RAPPORT, 9)
        self.assertEqual(sig.id, "SIG-00009")
        self.assertEqual(sig.source, "SCAN")
        self.assertEqual(sig.ip, "")
        self.assertEqual(sig.cible, "backend")
        self.assertEqual(sig.type, "FAILLE")
        self.assertEqual(sig.timestamp, "2026-10-05T10:05:00Z")
        self.assertEqual(sig.gravite, "CRITIQUE")
        self.assertEqual(sig.message, "Faille S3649 : injection SQL possible")

    def test_gravites_scan(self):
        for sev, attendu in [("critical", "ELEVEE"), ("MAJOR", "MOYENNE"),
                             ("Minor", "FAIBLE"), ("info", "FAIBLE")]:
            r = dict(RAPPORT, severity=sev)
            self.assertEqual(normaliser_scan(r, 1).gravite, attendu)

    def test_cle_manquante(self):
        r = dict(RAPPORT)
        del r["date"]
        with self.assertRaises(ValueError):
            normaliser_scan(r, 1)


if __name__ == "__main__":
    unittest.main()