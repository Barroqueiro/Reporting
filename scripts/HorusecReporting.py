# Script developed to sumarize a horusec json report

import re
import json
import argparse
from datetime import datetime
from modules.tree import start
from jinja2 import Environment, FileSystemLoader

def parse_horusec_json(vuln_list):
    """
    parse_horusec_json parses a json output for a horusec scan, and turns it into a dictionary containing vulnerabilities split by their severity, 
    and inside by their description with diferente instances being agregated

    :param vuln_list: list of vulnerabilities from the horusec json file
    :return: dict with vulnerbailities ordered by severity
    """

    vulns_by_severity = {"CRITICAL":{},"HIGH":{},"MEDIUM":{},"LOW":{},"UNKNOWN":{}}

    # Return empty list if no vulnerbailities
    if vuln_list is None:
        return vulns_by_severity

    for v in vuln_list:

        vuln = v["vulnerabilities"]
        location = vuln["file"] + " at line " + vuln["line"]
        hash = vuln["vulnHash"]
        severity = vuln["severity"]
        details = vuln["details"].replace("* Possible vulnerability detected: ","\n\n")
        details = re.sub('\([1-9]*/[1-9]*\)',"Problem: ",details)


        if details in vulns_by_severity[severity]:
            vulns_by_severity[severity][details]["list_instances"].append({"location":location,"hash":hash})
        else: 
            vulns_by_severity[severity][details] = {"list_instances":[{"location":location,"hash":hash}]}

    list_of_instances = []
    for key in vulns_by_severity:
        for k in vulns_by_severity[key]:
            list_of_instances = []
            for instance in vulns_by_severity[key][k]["list_instances"]:
                list_of_instances.append(instance["location"])
            vulns_by_severity[key][k]["tree"] = start(list_of_instances)

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

    with open(config["json"],"r",encoding="UTF-8") as horu:
        data = json.loads(horu.read())

    today = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    vuln_list = data["analysisVulnerabilities"]
    vulns = parse_horusec_json(vuln_list)

    styles = config["output_styles"].split(",")
    for s in styles:
        if s == "HTML":
            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('HorusecTemplateHTML.jinja2')
            colors = {"CRITICAL":"#F3836B","HIGH":"#F1A36A","MEDIUM":"#F9D703","LOW":"#6AB4F1","UNKNOWN":"#53DAC1"}
            output_from_parsed_template = template.render(vulns=vulns,today=today,colors=colors)

            with open(config["output"]+".html","w") as f:
                f.write(output_from_parsed_template)

        if s == "MD":
            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('HorusecTemplateMD.jinja2')
            appendix = env.get_template('HorusecTemplateAppendixMD.jinja2')
            output_from_parsed_template = template.render(vulns=vulns)
            output_from_parsed_template_appendix = appendix.render(vulns=vulns)

            with open(config["output"]+".md","w") as f:
                f.write(output_from_parsed_template)
            with open(config["output"]+"Appendix"+".md","w") as f:
                f.write(output_from_parsed_template_appendix)

if __name__ == "__main__":
    main()