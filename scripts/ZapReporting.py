# Script developed to sumarize a Zap json report 

import json
import argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def parse_zap_json(sites):
    """
    parse_zap_json parses a json output form a zap run, and outputs a dictionary with the severity of the vulnerabilities found as well as information about them, 
    a lot of parsing is done as the output is formated for HTML

    :param sites: List of sites found by zap within json format
    :return: Dictionary with the vulnerabilities organized by severity
    """

    ret_sites = []
    for s in sites:
        if s["alerts"] == []:
            continue
        site={}
        site["name"] = s["@name"]
        site["host"] = s["@host"]
        site["port"] = s["@port"]
        site["ssl"] = s["@ssl"]
        vulns_by_severity = {"HIGH":[],"MEDIUM":[],"LOW":[],"INFORMATIONAL":[],"IGNORED":[]}

        for a in s["alerts"]:
            id = a["alertRef"]
            name = a["name"]
            risk = a["riskdesc"].split(" ")
            severity = risk[0]
            confidence = risk[1].replace("(","")
            confidence = confidence.replace(")","")
            instances = a["instances"]
            solution = a["solution"]
            references = a["reference"].split("<p>")[1:]
            if "cweid" in a and int(a["cweid"]) > 0:
                cwe = a["cweid"]
            else:
                cwe = "NOT APPLICABLE"

            vulns_by_severity[severity.upper()].append({"id":id,
                                                        "name":name,
                                                        "confidence":confidence,
                                                        "instances":instances,
                                                        "solution":solution,
                                                        "references":references,
                                                        "cwe":cwe})
        
        site["vulns"] = vulns_by_severity    

        if "ignoredAlerts" in s:
            for a in s["ignoredAlerts"]:
                id = a["alertRef"]
                name = a["name"]
                risk = a["riskdesc"].split(" ")
                severity = "IGNORED"
                confidence = "High"
                instances = a["instances"]
                solution = a["solution"]
                references = a["reference"].split("<p>")[1:]
                if "cweid" in a:
                    cwe = a["cweid"]
                else:
                    cwe = "NOT APPLICABLE"
                vulns_by_severity[severity.upper()].append({"id":id,
                                                            "name":name,
                                                            "confidence":confidence,
                                                            "instances":instances,
                                                            "solution":solution,
                                                            "references":references,
                                                            "cwe":cwe})
        
        ret_sites.append(site)

    return ret_sites

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

    with open(config["json"],"r",encoding="UTF-8") as zap:
        data = json.loads(zap.read())

    today = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    sites = data["site"]
    vulns = parse_zap_json(sites)

    styles = config["output_styles"].split(",")
    for s in styles:
        if s == "HTML":

            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"), autoescape=True)
            template = env.get_template('ZapTemplateHTML.jinja2')
            colors = {"HIGH":"#F1A36A","MEDIUM":"#F9D703","LOW":"#6AB4F1","INFORMATIONAL":"#53DAC1","IGNORED":"#50C878"}
            output_from_parsed_template = template.render(vulns=vulns,today=today,colors=colors)
            with open(config["output"]+".html","w") as f:
                f.write(output_from_parsed_template)

        if s == "MD":
            
            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"))
            template = env.get_template('ZapTemplateMD.jinja2')
            appendix = env.get_template('ZapTemplateAppendixMD.jinja2')
            output_from_parsed_template = template.render(vulns=vulns)
            output_from_parsed_template_appendix = appendix.render(vulns=vulns)
            with open(config["output"]+".md","w") as f:
                f.write(output_from_parsed_template)
            with open(config["output"]+"Appendix"+".md","w") as f:
                f.write(output_from_parsed_template_appendix)

if __name__ == "__main__":
    main()