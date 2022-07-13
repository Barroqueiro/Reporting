# Script developed to sumarize a dockle json report

import json
import argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def parse_dockle_json(vuln_list):
    """
    parse_dockle_json parses a json output form a dockle run, and outputs a dictionary with the severity of the vulnerabilities found as well as information about them

    :param vuln_list: List of vulnerabilities found by dockle in json format
    :return: Dictionary with the vulnerabilities organized by severity
    """
    vulns_by_severity = {"FATAL":[],"WARN":[],"INFO":[]}

    for v in vuln_list:
        code = v["code"]
        title = v["title"]
        level = v["level"]
        alerts = v["alerts"]
        vulns_by_severity[level].append({"code":code,"title":title,"alerts":alerts})

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

    with open(config["json"],"r",encoding="UTF-8") as dockle:
        data = json.loads(dockle.read())

    today = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    vuln_list= data["details"]
    vulns = parse_dockle_json(vuln_list)

    styles = config["output_styles"].split(",")
    for s in styles:
        if s == "HTML":

            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('DockleTemplateHTML.jinja2')
            colors = {"FATAL":"#F3836B","WARN":"#FFCD00","INFO":"#53DAC1"}
            output_from_parsed_template = template.render(vulns=vulns,today=today,colors=colors)
            with open(config["output"]+".html","w") as f:
                f.write(output_from_parsed_template)

        if s == "MD":
            
            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('DockleTemplateMD.jinja2')
            output_from_parsed_template = template.render(vulns=vulns)
            with open(config["output"]+".md","w") as f:
                f.write(output_from_parsed_template)

if __name__ == "__main__":
    main()