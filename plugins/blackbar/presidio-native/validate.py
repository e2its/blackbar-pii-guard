"""
Validation harness for the blackbar analyzer.

Runs a corpus of dense, synthetic multilingual documents (clinical reports +
banking/administrative letters) against a running analyzer and reports, per
document, which expected entity types were FOUND vs MISSED, plus EXTRA hits.
Use it to compare backends:

    python validate.py http://localhost:5099   # native md
    python validate.py http://localhost:5002   # docker md
    python validate.py http://localhost:5003   # docker lg

All values are synthetic/fake. `expect` lists the entity types a privacy tool
should catch in each document (best-effort target, not a strict contract).
"""
import json
import sys
import urllib.request

THRESHOLD = 0.5  # mirrors the blackbar client default

CORPUS = [
    # ---- Spanish: clinical report ---------------------------------------- #
    dict(id="es-clinico", lang="es", expect={
        "PERSON", "DATE_TIME", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "ES_NIF", "ES_SSN", "HEALTH_RECORD", "ICD10_CODE"},
        text=(
            "INFORME CLÍNICO — Hospital Universitario La Paz, Madrid.\n"
            "Paciente: Ana María Rodríguez Gómez, nacida el 14/03/1985, "
            "DNI 12345678Z, nº de afiliación a la seguridad social 28 12345678 42.\n"
            "Domicilio: Calle Mayor 12, 3ºB, 28013 Madrid. Tel: +34 612 345 678, "
            "email ana.rodriguez@correo.es.\n"
            "Nº de historia clínica: 884512. Médico responsable: Dra. Laura Fernández.\n"
            "Diagnóstico principal: diabetes mellitus tipo 2 (CIE-10 E11.9) e "
            "hipertensión esencial (I10). Tratamiento: metformina 850 mg y enalapril 10 mg.")),

    # ---- Spanish: banking letter ----------------------------------------- #
    dict(id="es-banca", lang="es", expect={
        "PERSON", "IBAN_CODE", "CREDIT_CARD", "SWIFT_BIC", "EU_VAT",
        "EMAIL_ADDRESS", "LOCATION"},
        text=(
            "Estimado Sr. Carlos Pérez Ruiz:\n"
            "Le confirmamos la domiciliación en su cuenta IBAN "
            "ES91 2100 0418 4502 0005 1332 (BIC CAIXESBBXXX) y el cargo en su "
            "tarjeta 4111 1111 1111 1111.\n"
            "Datos fiscales de la empresa: VAT ESB12345674, domicilio social en "
            "Avenida Diagonal 640, 08017 Barcelona. Contacto: tesoreria@empresa.es.")),

    # ---- English: clinical + insurance ----------------------------------- #
    dict(id="en-clinical", lang="en", expect={
        "PERSON", "DATE_TIME", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "ICD10_CODE", "HEALTH_RECORD"},
        text=(
            "DISCHARGE SUMMARY — Massachusetts General Hospital, Boston.\n"
            "Patient: John Michael Smith, DOB 06/22/1979, SSN 078-05-1120, "
            "address 47 Beacon Street, Boston, MA 02108. Phone (617) 555-0142, "
            "email john.smith@example.com.\n"
            "Medical record number: 5582019. Attending: Dr. Emily Carter.\n"
            "Diagnosis: asthma (ICD-10 J45.9) and essential hypertension (I10). "
            "Plan: albuterol inhaler and lisinopril 10 mg daily.")),

    # ---- English: financial --------------------------------------------- #
    dict(id="en-finance", lang="en", expect={
        "PERSON", "IBAN_CODE", "CREDIT_CARD", "SWIFT_BIC", "EMAIL_ADDRESS",
        "CRYPTO", "IP_ADDRESS"},
        text=(
            "Dear Ms. Sarah Connor,\nYour wire to IBAN "
            "GB29 NWBK 6016 1331 9268 19 (SWIFT NWBKGB2L) was received. "
            "Backup card on file: 5500 0000 0000 0004.\n"
            "Crypto refund address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. "
            "Last login from IP 203.0.113.42. Questions: support@bank.com.")),

    # ---- French: clinical (NIR is also a health identifier) -------------- #
    dict(id="fr-clinique", lang="fr", expect={
        "PERSON", "DATE_TIME", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "FR_NIR_SSN", "ICD10_CODE"},
        text=(
            "COMPTE RENDU — Hôpital de la Pitié-Salpêtrière, Paris.\n"
            "Patient : Jean-Pierre Dubois, né le 02/11/1984, numéro de sécurité "
            "sociale 1 84 12 75 116 001 42, domicilié 10 Rue de Rivoli, 75004 Paris.\n"
            "Téléphone +33 6 12 34 56 78, courriel jp.dubois@exemple.fr.\n"
            "Diagnostic : diabète de type 2 (CIM-10 E11.9). Traitement : metformine.")),

    # ---- German: banking + tax ------------------------------------------ #
    dict(id="de-bank", lang="de", expect={
        "PERSON", "IBAN_CODE", "SWIFT_BIC", "EU_VAT", "DE_STEUER_ID",
        "LOCATION", "EMAIL_ADDRESS"},
        text=(
            "Sehr geehrter Herr Hans Müller,\nwir bestätigen Ihre IBAN "
            "DE89 3704 0044 0532 0130 00 (BIC COBADEFFXXX). "
            "Ihre Steueridentifikationsnummer 12345678901 wurde erfasst. "
            "Umsatzsteuer-ID VAT DE123456789.\nAnschrift: Hauptstraße 5, 10115 "
            "Berlin. Kontakt: info@firma.de.")),

    # ---- Italian: clinical + fiscal code -------------------------------- #
    dict(id="it-clinico", lang="it", expect={
        "PERSON", "DATE_TIME", "LOCATION", "PHONE_NUMBER",
        "IT_FISCAL_CODE", "ICD10_CODE", "EMAIL_ADDRESS"},
        text=(
            "REFERTO MEDICO — Ospedale Niguarda, Milano.\n"
            "Paziente: Marco Rossi, nato il 10/12/1985, codice fiscale "
            "RSSMRA85T10A562S, residente in Via Roma 15, 20121 Milano.\n"
            "Telefono +39 02 1234 5678, email marco.rossi@esempio.it.\n"
            "Diagnosi: ipertensione essenziale (ICD-10 I10). Terapia: ramipril 5 mg.")),

    # ---- Portuguese: administrative + NIF ------------------------------- #
    dict(id="pt-admin", lang="pt", expect={
        "PERSON", "DATE_TIME", "LOCATION", "PHONE_NUMBER", "PT_NIF",
        "IBAN_CODE", "EMAIL_ADDRESS"},
        text=(
            "Exmo. Sr. João Pedro Silva,\nregistámos o seu NIF de contribuinte "
            "123456789 e a conta IBAN PT50 0002 0123 1234 5678 9015 4.\n"
            "Morada: Rua Augusta 100, 1100-053 Lisboa. Nascido em 05/07/1990. "
            "Telefone +351 912 345 678, email joao.silva@exemplo.pt.")),
]


def analyze(base, text, lang):
    data = json.dumps({"text": text, "language": lang}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/analyze", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5002"
    print(f"### backend: {base}\n")
    total_exp = total_found = 0
    all_missing = {}
    for doc in CORPUS:
        res = [x for x in analyze(base, doc["text"], doc["lang"]) if x["score"] >= THRESHOLD]
        found = {x["entity_type"] for x in res}
        exp = doc["expect"]
        hit = exp & found
        missing = exp - found
        extra = found - exp
        total_exp += len(exp)
        total_found += len(hit)
        if missing:
            all_missing[doc["id"]] = missing
        print(f"[{doc['lang']}] {doc['id']:14s} {len(hit)}/{len(exp)} expected")
        print(f"     found:   {', '.join(sorted(found)) or '-'}")
        if missing:
            print(f"     MISSING: {', '.join(sorted(missing))}")
        if extra:
            print(f"     extra:   {', '.join(sorted(extra))}")
    pct = 100 * total_found / total_exp if total_exp else 0
    print(f"\n### COVERAGE: {total_found}/{total_exp} expected entity types ({pct:.0f}%)")
    if all_missing:
        print("### MISSES by doc:")
        for k, v in all_missing.items():
            print(f"   {k}: {', '.join(sorted(v))}")


if __name__ == "__main__":
    main()
