# Script developed to sumarize a trivy json report

import json
import argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def parse_trivy_json(vuln_list):
    """
    parse_trivy_json parses a json output form a trivy run, and outputs a dictionary with the severity of the vulnerabilities found as well as information about them, 
    some values do not have information because theya re not provided by trivy

    :param vuln_list: List of vulnerabilities found by trivy in json format
    :return: Dictionary with the vulnerabilities organized by severity
    """

    vulns_by_severity = {"CRITICAL":{},"HIGH":{},"MEDIUM":{},"LOW":{},"UNKNOWN":{}}

    for v in vuln_list:
        if "VulnerabilityID" in v:
            id = v["VulnerabilityID"]
        else:
            id = "NOT APPLICABLE"
        if "PkgName" in v:
            pkg_name = v["PkgName"]
        else:
            pkg_name = "NOT APPLICABLE"
        if "InstalledVersion" in v:
            installed_version = v["InstalledVersion"]
        else:
            installed_version = "NOT APPLICABLE"
        if "FixedVersion" in v:
            fixed_version = v["FixedVersion"]
        else:
            fixed_version = "STILL NO FIX"
        if "PrimaryURL" in v:
            vuln_url = v["PrimaryURL"]
        else: 
            vuln_url = "NO URL"
        if "Title" in v:
            title = v["Title"]
        else:
            title = "NO TITLE"
        if "Description" in v:
            description = v["Description"]
        else:
            description = "NO DESCRIPTION"
        if "Severity" in v:
            severity = v["Severity"]
        else:
            severity = "NO SEVERITY"
        if "CweIDs" in v:
            cwes = [x.replace("CWE-","") for x in v["CweIDs"]]
        else:
            cwes = []

        count_avg = 0
        if "CVSS" in v:
            cvss = v["CVSS"]
            sum_avg = 0
            for cv in cvss:
                if "V3Score" in cvss[cv]:
                    count_avg += 1
                    sum_avg += cvss[cv]["V3Score"]
        if count_avg > 0:
            avg = round(sum_avg/count_avg,1)
        else:
            avg = "NOT KNOWN"

        if id in vulns_by_severity[severity]:
            vulns_by_severity[severity][id]["pkg_name"].append(pkg_name)
        else:
            vulns_by_severity[severity][id] = {"id":id,"pkg_name":[pkg_name],"installed_version":installed_version,"fixed_version":fixed_version,"vuln_url":vuln_url,"title":title,"description":description,"cwes":cwes,"cvss":avg}

    return vulns_by_severity

def main():
    """
    main parse the arguments needed for execution, output the requested types and create the dictionaries of vulnerabilities
    """
    parser = argparse.ArgumentParser(description="Comparing diferences in json file on a certain keyword")
    parser.add_argument('--json', type=str,
                        help='Json to analyse')
    parser.add_argument('--current-path', type=str,
                        help='Current path')
    parser.add_argument('--output-styles', type=str,
                        help='Output style')
    parser.add_argument('--output', type=str,
                        help='File to output the result')
    args = parser.parse_args()
    config = vars(args)

    with open(config["json"],"r",encoding="UTF-8") as trivy:
        data = json.loads(trivy.read())

    today = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    vuln_list = data["Results"][0]["Vulnerabilities"]
    vulns = parse_trivy_json(vuln_list)

    styles = config["output_styles"].split(",")
    for s in styles:
        if s == "HTML":

            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('TrivyTemplateHTML.jinja2')
            colors = {"CRITICAL":"#F3836B","HIGH":"#F1A36A","MEDIUM":"#F9D703","LOW":"#6AB4F1","UNKNOWN":"#53DAC1"}
            output_from_parsed_template = template.render(vulns=vulns,today=today,colors=colors)
            with open(config["output"]+".html","w") as f:
                f.write(output_from_parsed_template)

        if s == "MD":

            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('TrivyTemplateMD.jinja2')
            output_from_parsed_template = template.render(vulns=vulns)
            with open(config["output"]+".md","w") as f:
                f.write(output_from_parsed_template)

if __name__ == "__main__":
    main()