# Script developed to sumarize a Gitleaks json report

import sys
import json
import hashlib
import argparse
from datetime import datetime
from modules.tree import start
from jinja2 import Environment, FileSystemLoader

def parse_secrets_json(secret_list,ignore):
    """
    parse_secrets_json parses a json output from GitLeaks and transform it into a dictionary containing Secrets and Accepted secrets, 
    these acepted secrets are a hash also computed by this function and passed within the ignore file

    :param secret_list: list with secrets found by GitLeaks
    :ignore: List of hashes of secrets to ignore and make as accepted secrets
    """
    secrets = {"SECRETS":[],"ACCEPTED SECRETS":[]}
    ret = 0

    for s in secret_list:
        date = s["Date"]
        del s["Date"]
        h = hashlib.sha256(str(s).encode()).hexdigest()

        if h in ignore:
            status = "ACCEPTED SECRETS"
        else:
            status = "SECRETS"
            ret = 1

        description = s["Description"]
        match = s["Match"]
        location = s["File"] + " from line " + str(s["StartLine"]) + " to line " + str(s["EndLine"])
        commit = s["Commit"]
        Author = s["Email"]

        secrets[status].append({"description":description,"match":match,"location":start([location]),"commit":commit,"author":Author,"hash":h,"date":date})

    return secrets,ret

        
def main():
    """
    main parse the arguments needed for execution, output the requested types and create the dictionaries of secrets
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
    parser.add_argument('--ignore', type=str,
                        help='Secrets to ignore')       
    args = parser.parse_args()
    config = vars(args)

    with open(config["json"],"r", encoding="UTF-8") as secrets:
        data = json.loads(secrets.read())

    with open(config["ignore"],"r", encoding="UTF-8") as ignore:
        ig = ignore.read().split("\n")

    today = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    secrets,ret = parse_secrets_json(data,ig)

    styles = config["output_styles"].split(",")
    for s in styles:
        if s == "HTML":

            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"),autoescape=True)
            template = env.get_template('SecretsTemplateHTML.jinja2')
            colors = {"SECRETS":"#F3836B","ACCEPTED SECRETS":"#50C878"}
            output_from_parsed_template = template.render(secrets=secrets,today=today,colors=colors)
            with open(config["output"]+".html","w") as f:
                f.write(output_from_parsed_template)

        if s == "MD":

            env = Environment(loader=FileSystemLoader(config["current_path"]+"/templates"))
            template = env.get_template('SecretsTemplateMD.jinja2')
            output_from_parsed_template = template.render(secrets=secrets)
            with open(config["output"]+".md","w") as f:
                f.write(output_from_parsed_template)
    
    sys.exit(ret)

if __name__ == "__main__":
    main()
