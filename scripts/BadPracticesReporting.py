# Script developed to sumarize prospector and radon json reports

import sys
import json
import argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


# Translate the 3 types of structures that radon analyses 
RADON_DICT = {
    "F" : "Function",
    "M" : "Method",
    "C" : "Class"
}


# Order the issues by line
# Print the most important atributes by issue found
def make_vulns(messages):
    messages = sorted(messages,key=lambda messages:messages["location"]["line"] if messages["location"]["line"] is not None else 0)
    vulns = {"Issues":[]}
    ret = 0
    for msg in messages:
        ret = 1
        tool = msg["source"]
        code = msg["code"]
        line = msg["location"]["line"]
        m = msg["message"]
        vulns["Issues"].append({"tool":tool,"code":code,"line":line,"message":m})
    
    return ret,vulns

# Print the radon legend
# Parse the radon output by line and extracting all componenents
# Print each structure and their code complexity
def make_radon(radon):
    res = {"F":[],"E":[],"D":[],"C":[],"B":[],"A":[]}
    radon = radon[1:]
    for complexity in radon:
        complexity = complexity.replace("\n","")
        complexity_split = complexity.split(" ")[4:]
        if complexity_split[0] in RADON_DICT:
            block = RADON_DICT[complexity_split[0]]
        else:
            continue
        line = complexity_split[1].split(":")[0]
        name = complexity_split[2]
        score = complexity_split[-1]
        res[score].append({"block":block,"line":line,"name":name})
    return res

# Load the prospector and radon reports
# Call the designated functions to output the summaries of both tools
def main():
    parser = argparse.ArgumentParser(description="Comparing diferences in json file on a certain keyword")
    parser.add_argument('--json', type=str,
                        help='Json to analyse')
    parser.add_argument('--txt', type=str,
                        help='Txt to analyse')
    parser.add_argument('--current-path', type=str,
                        help='Current path')
    parser.add_argument('--output-styles', type=str,
                        help='Output style')
    parser.add_argument('--output', type=str,
                        help='File to output the result')
    args = parser.parse_args()
    config = vars(args)

    with open(config["json"],"r",encoding="UTF-8") as prosp:
        data = json.loads(prosp.read())

    with open(config["txt"],"r",encoding="UTF-8") as rad:
        radon = rad.readlines()

    today = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ret,vulns = make_vulns(data["messages"])
    radon_cc = make_radon(radon)

    styles = config["output_styles"].split(",")
    for s in styles:
        if s == "HTML":
            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('BadPracticesTemplateHTML.jinja2')
            radon_colors = {"F":"#E12525","E":"#E15625","D":"#E1A525","C":"#E8F307","B":"#81F307","A":"#3DF307"}
            filename = config["output"].split("/")[-1].replace(".html","").replace("\\","/") + ".py"
            output_from_parsed_template = template.render(vulns=vulns,radon=radon_cc,today=today,radon_colors=radon_colors,filename=filename)
            with open(config["output"]+".html","w") as f:
                f.write(output_from_parsed_template)
        if s == "MD":
            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('BadPracticesTemplateMD.jinja2')
            output_from_parsed_template = template.render(vulns=vulns,radon=radon_cc,filename=filename)

            with open(config["output"]+".md","w") as f:
                f.write(output_from_parsed_template)
            
    sys.exit(ret)

if __name__ == "__main__":
    main()