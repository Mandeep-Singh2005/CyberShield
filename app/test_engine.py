from vulnerability_engine import query_nvd

findings = query_nvd(
    "cpe:/a:vsftpd:vsftpd:2.3.4"
)

for finding in findings:
    print("--------------------------------")
    print("CVE:", finding["cve"])
    print("CVSS:", finding["cvss"])
    print("Severity:", finding["severity"])
    print("Description:", finding["description"])
