import requests
import argparse
import json
import csv
import sys
import time
from datetime import datetime

#cargamos config.json
try:
    f = open('config.json', 'r')
    config = json.load(f)
    CVE_API = config['cve_api']
    CPE_API = config['cpe_api']
    f.close()
except FileNotFoundError:
    print("No existe config.json")
    sys.exit(1)


def buscar_cpe(keyword):
    print(f"Buscando CPE para: {keyword}...")

    params = {}
    params['keywordSearch'] = keyword
    params['resultsPerPage'] = 1

    try:
        time.sleep(6)

        response = requests.get(CPE_API, params=params)

        if response.status_code == 200:
            data = response.json()
            # Comprobamos si hay productos de forma basica
            if 'products' in data and len(data['products']) > 0:
                cpe_name = data['products'][0]['cpe']['cpeName']
                print(f"cpe encontrado: {cpe_name}")
                return cpe_name
            else:
                print("No se encontraron cpes con ese nombre.")
                return None
        else:
            print(f"Error API: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error de conexión (CPE): {e}")
        return None


def buscar_cves(cpe_name, severity, start_date, end_date):
    print(f"Buscando CVEs para el CPE: {cpe_name}...")

    params = {}
    params['cpeName'] = cpe_name

    if severity != None:
        params['cvssV3Severity'] = severity.upper()

    if start_date != None and end_date != None:
        params['pubStartDate'] = start_date + "T00:00:00.000"
        params['pubEndDate'] = end_date + "T23:59:59.999"

    try:
        time.sleep(6)

        response = requests.get(CVE_API, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error API CVE: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error obteniendo CVEs: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description='buscador de cpes y cves (NVD API 2.0)')
    parser.add_argument('product', help='nombre del producto o CPE (ej: "apache" o "cpe:2.3:...")')
    parser.add_argument('-f', '--file', help='nombre del csv de salida')
    parser.add_argument('--filter', help='filtrar por severidad (LOW, MEDIUM, HIGH, CRITICAL)')
    parser.add_argument('--date', help='rango de fechas (formato: YYYY-MM-DD/YYYY-MM-DD)')

    args = parser.parse_args()

    # vemos si hay un cpe como arg y si no buscamos el cpe
    product_name = args.product
    cpe_target = ""

    if product_name.lower().startswith("cpe:"):
        cpe_target = product_name
    else:
        cpe_target = buscar_cpe(product_name)
        if cpe_target == None:
            sys.exit(1)

    # procesamos fechas
    s_date = None
    e_date = None

    if args.date:
        try:
            fechas = args.date.split('/')
            s_date = fechas[0]
            e_date = fechas[1]
            # validamos formato
            datetime.strptime(s_date, '%Y-%m-%d')
            datetime.strptime(e_date, '%Y-%m-%d')
        except:
            print("Error: El formato de fecha debe ser YYYY-MM-DD/YYYY-MM-DD")
            sys.exit(1)

    # obtenemos cves
    data = buscar_cves(cpe_target, args.filter, s_date, e_date)

    if data == None:
        print("No se encontraron vulnerabilidades para los criterios dados")
        sys.exit(0)

    if 'vulnerabilities' not in data:
        print("No se encontraron vulnerabilidades para los criterios dados")
        sys.exit(0)

    results = []
    vuln_list = data['vulnerabilities']
    cantidad = len(vuln_list)
    print(f"Procesando {cantidad} vulnerabilidades encontradas...")

    for item in vuln_list:
        cve = item['cve']
        cve_id = cve['id']

        description = "N/A"
        if 'descriptions' in cve:
            lista_desc = cve['descriptions']
            if len(lista_desc) > 0:
                description = lista_desc[0]['value']
                description = description.replace('\n', ' ')

        pub_date = "N/A"
        if 'published' in cve:
            pub_date = cve['published']

        base_score = "N/A"
        severity = "N/A"
        vector = "N/A"

        metrics_data = {}
        if 'metrics' in cve:
            metrics_data = cve['metrics']

        cvss_metrics = []
        #miramos si es v3.1 o v3.0 con ifs
        if 'cvssMetricV31' in metrics_data:
            cvss_metrics = metrics_data['cvssMetricV31']
        elif 'cvssMetricV30' in metrics_data:
            cvss_metrics = metrics_data['cvssMetricV30']

        if len(cvss_metrics) > 0:
            datos_cvss = cvss_metrics[0]['cvssData']
            base_score = datos_cvss['baseScore']
            severity = datos_cvss['baseSeverity']
            vector = datos_cvss['vectorString']

        #sacamos cwe
        cwe_id = "N/A"
        if 'weaknesses' in cve:
            weaknesses = cve['weaknesses']
            if len(weaknesses) > 0:
                if 'description' in weaknesses[0]:
                    desc_we = weaknesses[0]['description']
                    if len(desc_we) > 0:
                        cwe_id = desc_we[0]['value']

        row = [
            args.product,
            cpe_target,
            cve_id,
            severity,
            base_score,
            vector,
            description,
            pub_date,
            cwe_id
        ]
        results.append(row)

        print(f" -> {cve_id} | {severity} | {base_score}")

    #exportamos csv
    if args.file:
        headers = [
            "Nombre del producto", "CPE", "CVE", "Severity",
            "CVSS3.1 Base Score", "Vector (URL)", "Descripcion",
            "Fecha de publicacion", "CWE id"
        ]
        try:
            archivo_csv = open(args.file, 'w', newline='', encoding='utf-8')
            writer = csv.writer(archivo_csv)
            writer.writerow(headers)
            for r in results:
                writer.writerow(r)
            archivo_csv.close()

            print(f"[SUCCESS] Resultados guardados en: {args.file}")
        except Exception as e:
            print(f"Error escribiendo el archivo CSV: {e}")

main()