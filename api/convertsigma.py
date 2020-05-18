import subprocess
import os
import re
import boto3
import botocore
import sys
sys.path.append('/home/jovyan/')

class ConvertSigma:
    
    def __init__(self):
        """
            Initialise the variables
        """
        self.directory = "sigma/rules/osquery"
        self.config = "sigma/config/osquery.yml"
        self.savetodir = "sigma/rules/output" 
        self.sourceregex = "sourcetype = (.*?) AND "

    def sigmac(self, rulefile):
        """
            Sigma Converter - mainly to convert sigma rules into SQL format and then call getsourcetype()
            Required to convert the severity to digits for ticketing platform.
        """
        result = subprocess.run(['python3', 'sigma/tools/sigmac', '-c', self.config, '-t', 'sql', rulefile], stdout=subprocess.PIPE, encoding='utf-8')
        rule = result.stdout
        stype = self.get_sourcetype(rule, rulefile)
        gtitle = "%s" % (self.get_title(rulefile))
        gtitle = gtitle.split("title: ")[1]
        glevel = "%s" % (self.get_level(rulefile))
        glevel = glevel.split("level: ")[1]
        if "high" in glevel:
            glevel = "3"
        elif "medium" in glevel:
            glevel = "2"
        elif "low" in glevel:
            glevel = "1"
        else:
            sys.exit(1)
        self.create_file(stype, rule, gtitle, glevel)

    def get_sourcetype(self, rule, rulefile):
        """
            Get the sourcetype of each rule
        """
        try:
            sourcetype = re.search(self.sourceregex, rule).group(1).replace('"', '')
            return sourcetype
        except:
            print("[-] Sourcetype error for %s" % (rulefile))
            sys.exit()

    def create_file(self, sourcetype, rule, title, level):
        """
            Store the rule into rules file
        """
        rule = self.clean_rule(rule)
        saveto = "%s/%s.rules" % (self.savetodir, sourcetype)
        if not os.path.isdir(self.savetodir):
            os.makedirs(self.savetodir)

        if not os.path.exists(saveto):
            with open(saveto, 'w'): pass

        saveline = "%s && %s && %s" % (title, level, rule)
        if not self.check_ruleexist(saveto, rule):
            print(saveline, file=open(saveto, 'a'))

    def clean_rule(self, rule):
        """
            Clean the rule before storing them into rules file
        """
        return re.sub(self.sourceregex, '', rule)[1:-2]

    def check_ruleexist(self, fname, rule):
        """
            Check if rule already exist in rules file
        """
        with open(fname) as rfile:
            return any(rule in line for line in rfile)

    def get_title(self, rulefile):
        """
            Grep the rulefile and retrieve title
        """
        proc1 = subprocess.Popen(["cat", rulefile],stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', "title"], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc1.stdout.close()
        out, err = proc2.communicate()
        output = out.decode('utf-8').split('\n')
        return output[0]

    def get_level(self, rulefile):
        """
            Grep the rulefile and retrieve level
        """
        proc1 = subprocess.Popen(["cat", rulefile],stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', "-w", "level"], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc1.stdout.close()
        out, err = proc2.communicate()
        output = out.decode('utf-8').split('\n')
        return output[0]

    def wipe_rules(self):
        """
            Delete all .rules and sigma files
        """
        if os.path.exists(self.savetodir):
            for root, dirs, files in os.walk(self.savetodir):
                for f in files:
                    if f.endswith(".rules"):
                        rulesfile = os.path.join(root, f)
                        os.remove(rulesfile)
                        print("[-] Deleting " + f)
        if os.path.exists(self.directory):
            for root, dirs, files in os.walk(self.directory):
                for f in files:
                    if f.endswith(".yaml"):
                        rulesfile = os.path.join(root, f)
                        os.remove(rulesfile)
                        print("[-] Deleting " + f)
        else:
            print("[-] Directory not found")

    def download_rules(self):
        """
            Download your sigma rules from S3 bucket
        """
        s3 = boto3.resource('s3')
        s3client = boto3.client('s3')
        my_bucket = s3.Bucket('your-s3-bucket')
        for file in my_bucket.objects.all():
            filename = "%s" % (file.key)
            if filename.endswith('.yaml'):
                if "rules/" in filename:
                    try:
                        savename = filename.split('rules/')[1]
                        pathtosave = 'sigma/rules/osquery/%s' % (savename)
                        s3client.download_file('your-s3-bucket', filename, pathtosave)
                        print("[+] Downloaded %s to %s" % (filename, pathtosave))
                    except:
                        print("[-] Error")

    def main(self):
        """
            Iterate the directory to look for all sigma rules
        """
        self.wipe_rules()
        self.download_rules()
        if os.path.exists(self.directory):
            for root, dirs, files in os.walk(self.directory):
                for f in files:
                    if f.endswith(".yml") or f.endswith(".yaml"):
                        print("[+] Processing Sigma input " + f)
                        rulefile = os.path.join(root, f)
                        self.sigmac(rulefile)
            print("[*] Completed - rules in sigma/rules/output")
        else:
            print("[-] Directory not found")

    if __name__ == '__main__':
        main()