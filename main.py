# -*- coding: utf-8 -*-
# 加载a.json文件
import json
results = []
with open('a.json', 'r', encoding="utf_8") as f:
    murphy_date = json.load(f)
sarif = {}
#向safi添加数据
sarif["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
sarif["version"] = "2.1.0"
sarif["runs"] = []
sarif["runs"].append({})
sarif["runs"][0]["tool"] = {}
sarif["runs"][0]["tool"]["driver"] = {}
sarif["runs"][0]["tool"]["driver"]["name"] = "Murphy-cli"
sarif["runs"][0]["tool"]["driver"]["rules"] = []
#遍历murphy_date的rules
for i in murphy_date["comps"]:
    if i["vulns"] == []:
        #如果vulns为空，跳过
        continue
    data = {}
    data["id"] = "murphysec-" + i["vulns"][0]["cve_id"]
    data["shortDescription"] = {}
    data["shortDescription"]["text"] = i["vulns"][0]["level"] + i["comp_name"] + i["comp_version"]
    data["fullDescription"] = {}
    data["fullDescription"]["text"] = i["vulns"][0]["level"] + i["comp_name"] + i["comp_version"]
    data["help"] = {}
    data["help"]["text"] = ""

    data["help"]["text"] = '* ' + str(i["vulns"][0]["description"])
    sarif["runs"][0]["tool"]["driver"]["rules"].append(data)
    res = {}
    res["ruleId"] = "murphysec-" + i["vulns"][0]["cve_id"]
    res["level"] = "warning"
    res["message"] = {}
    res["message"]["text"] = i["vulns"][0]["level"] + i["comp_name"] + i["comp_version"]
    res["locations"] = []
    locations = {}
    locations["physicalLocation"] = {}
    locations["physicalLocation"]["artifactLocation"] = {}
    locations["physicalLocation"]["artifactLocation"]["uri"] = "go.mod"
    locations["physicalLocation"]["region"] = {}
    locations["physicalLocation"]["region"]["startLine"] = 1
    res["locations"].append(locations)
    results.append(res)

sarif["runs"][0]["results"] = results
#将sarif写入文件
with open('a.sarif', 'w', encoding="utf_8") as f:
    json.dump(sarif, f, indent=4, separators=(',', ': '))


print(sarif)





