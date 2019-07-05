import git
import re
import  tempfile
import traceback
import datetime

rule_map = {
    "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
    "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
    "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]",
    "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Twilio API Key": "SK[a-z0-9]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
UNDERLINE = '\033[4m'

class RepoSecScan:

    def init_rules(self):
        self.rules = {}
        for key in rule_map.keys():
            self.rules[key] = re.compile(rule_map[key])


    def scan_one(self, content, cregex = {}):
        regex_matches = []
        try:
            allRules = {}
            for k1 in cregex.keys():
                allRules[k1] = cregex[k1]

            for k2 in self.rules.keys():
                allRules[k2] = self.rules[k2]

            for key in allRules:
                found_strings = self.rules[key].findall(content)
                for found_string in found_strings:
                    found_diff = content.replace(found_string, bcolors.WARNING + found_string + bcolors.ENDC)
                if found_strings:
                    foundRegex = {}
                    foundRegex['stringsFound'] = found_strings
                    foundRegex['printDiff'] = found_diff
                    foundRegex["strings"] = content
                    if key in self.rules.keys():
                        foundRegex["is_custom"] = False
                    else:
                        foundRegex["is_custom"] = True
                    regex_matches.append(foundRegex)
        except Exception as e:
            msg = traceback.format_exc()
            print(msg)
        return regex_matches


    def secRuleMatch(self, diffContent, commit_time, curCommitInfo, preCommitInfo, blobInfo, branch_name, customRegex = {}):
        regex_matches = []
        allRules = {}
        for k1 in customRegex.keys():
            allRules[k1] = customRegex[k1]

        for k2 in self.rules.keys():
            allRules[k2] = self.rules[k2]

        for key in allRules:
            found_strings = self.rules[key].findall(diffContent)
            for found_string in found_strings:
                found_diff = diffContent.replace(found_string, bcolors.WARNING + found_string + bcolors.ENDC)
            if found_strings:
                foundRegex = {}
                foundRegex['date'] = commit_time
                foundRegex['path'] = blobInfo.b_path if blobInfo.b_path else blobInfo.a_path
                foundRegex['branch'] = branch_name
                foundRegex['commit_mes'] = curCommitInfo.message
                foundRegex['diff'] = blobInfo.diff.decode('utf-8', errors='replace')
                foundRegex['stringsFound'] = found_strings
                foundRegex['printDiff'] = found_diff
                foundRegex['reason'] = key
                foundRegex['commitHash'] = curCommitInfo.hexsha
                foundRegex["parent_commitHash"] = preCommitInfo.hexsha
                foundRegex["parent_commit_mes"] = preCommitInfo.message
                if key in self.rules.keys():
                    foundRegex["is_custom"] = False
                else:
                    foundRegex["is_custom"] = True
                regex_matches.append(foundRegex)
        return regex_matches



    def clone_git_repo(self,git_url):
        project_path = tempfile.mkdtemp()
        print("begin cloning repo...")
        print(project_path)
        git.Repo.clone_from(git_url, project_path)
        print(project_path)

    def for_local_diff(self, local_path, path_inclusions=None, path_exclusions=None, sinceCommitHash = None, max_depth=1000000, cRegex = {}):
        scanResult = []
        try:
            localRepo = git.Repo(local_path)
            branches = localRepo.remotes.origin.fetch()

            for branchIte in branches:
                branchName = branchIte.name
                print(branchName)
                preCommit = None
                curCommit = None
                for commitIter in localRepo.iter_commits(branchName, max_count=1000000):
                    preCommit = curCommit
                    curCommit = commitIter
                    if preCommit is not None and curCommit is not None:
                        diff = curCommit.diff(preCommit, create_patch=True)
                        for blob in diff:
                            printableDiff = blob.diff.decode('utf-8', errors='replace')
                            print(printableDiff)
                            if printableDiff.startswith("Binary files"):
                                continue
                            commit_time = datetime.datetime.fromtimestamp(curCommit.committed_date).strftime(
                                '%Y-%m-%d %H:%M:%S')
                            scanResult = self.secRuleMatch(printableDiff, commit_time, curCommit, preCommit, blob,
                                         branchName, customRegex=cRegex)
        except Exception as e:
            msg = traceback.format_exc()
            print(msg)
        finally:
            return scanResult


if __name__ == '__main__':
    yj = RepoSecScan()
    yj.init_rules()
    scanResult = yj.for_local_diff('C:/uuu/microservice-mall', 1000)
    lth = len(scanResult)
    if lth == 0:
        print("未找到结果")
    else:
        print(lth)

